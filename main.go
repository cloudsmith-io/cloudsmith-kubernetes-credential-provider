package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type CloudsmithOIDCRequest struct {
	OIDCToken   string `json:"oidc_token"`
	ServiceSlug string `json:"service_slug"`
}

type CloudsmithOIDCResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

type CloudsmithCredentialProvider struct {
	config     *Config
	httpClient *http.Client
}

func NewCloudsmithCredentialProvider(cfg *Config) *CloudsmithCredentialProvider {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.InsecureSkipVerify {
		klog.Warning("TLS certificate verification disabled")
	}

	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			MaxIdleConns:        cfg.MaxIdleConns,
			MaxIdleConnsPerHost: cfg.MaxIdleConns,
			IdleConnTimeout:     cfg.IdleConnTimeout,
		},
	}

	provider := &CloudsmithCredentialProvider{
		config:     cfg,
		httpClient: httpClient,
	}

	klog.InfoS("Initialized Cloudsmith credential provider", "customHeaders", len(cfg.Headers))

	return provider
}

func (c *CloudsmithCredentialProvider) retryWithExponentialBackoff(ctx context.Context, req *http.Request) (*http.Response, error) {
	var lastErr error

	var originalBody []byte
	if req.Body != nil {
		var err error
		originalBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(originalBody))
	}

	backoff := wait.Backoff{
		Duration: c.config.RetryBackoffDuration,
		Factor:   c.config.RetryBackoffFactor,
		Jitter:   c.config.RetryBackoffJitter,
		Steps:    c.config.MaxRetryAttempts,
		Cap:      c.config.RetryBackoffCap,
	}

	var resp *http.Response
	err := wait.ExponentialBackoffWithContext(ctx, backoff, func(conditionCtx context.Context) (bool, error) {
		if originalBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(originalBody))
		}

		var err error
		resp, err = c.httpClient.Do(req.WithContext(conditionCtx))
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "HTTP request failed, will retry")
			return false, nil
		}

		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			klog.V(4).InfoS("HTTP request returned retryable error, will retry",
				"statusCode", resp.StatusCode)
			return false, nil
		}

		klog.V(4).InfoS("HTTP request successful",
			"statusCode", resp.StatusCode)

		return true, nil
	})

	if err != nil {
		if wait.Interrupted(err) {
			klog.ErrorS(lastErr, "All HTTP request attempts failed after timeout")
			return nil, fmt.Errorf("request failed after max attempts: %w", lastErr)
		}
		return nil, err
	}

	return resp, nil
}

func (c *CloudsmithCredentialProvider) exchangeTokenWithCloudsmith(ctx context.Context, oidcToken string) (string, error) {
	klog.V(4).InfoS("Starting OIDC token exchange with Cloudsmith")

	requestPayload := CloudsmithOIDCRequest{
		OIDCToken:   oidcToken,
		ServiceSlug: c.config.ServiceSlug,
	}

	jsonPayload, err := json.Marshal(requestPayload)
	if err != nil {
		klog.ErrorS(err, "Failed to marshal OIDC request payload")
		return "", fmt.Errorf("failed to marshal request payload: %w", err)
	}

	url := fmt.Sprintf("https://%s/openid/%s/", c.config.APIHost, c.config.OrgSlug)
	klog.InfoS("Exchanging OIDC token with Cloudsmith",
		"url", url,
		"serviceSlug", c.config.ServiceSlug,
		"orgSlug", c.config.OrgSlug)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		klog.ErrorS(err, "Failed to create HTTP request")
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	for headerName, headerValue := range c.config.Headers {
		req.Header.Set(headerName, headerValue)
		klog.V(4).InfoS("Set custom header", "header", headerName)
	}

	resp, err := c.retryWithExponentialBackoff(ctx, req)
	if err != nil {
		klog.ErrorS(err, "HTTP request to Cloudsmith failed")
		return "", fmt.Errorf("failed to make HTTP request to Cloudsmith: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		klog.ErrorS(err, "Failed to read Cloudsmith response body")
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	klog.V(4).InfoS("Received response from Cloudsmith",
		"statusCode", resp.StatusCode,
		"responseSize", len(body))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		klog.ErrorS(nil, "Cloudsmith API returned error status",
			"statusCode", resp.StatusCode,
			"response", string(body))
		return "", fmt.Errorf("Cloudsmith API returned status %d: %s", resp.StatusCode, string(body))
	}

	var cloudsmithResponse CloudsmithOIDCResponse
	if err := json.Unmarshal(body, &cloudsmithResponse); err != nil {
		klog.ErrorS(err, "Failed to unmarshal Cloudsmith response", "response", string(body))
		return "", fmt.Errorf("failed to unmarshal Cloudsmith response: %w", err)
	}

	if cloudsmithResponse.Error != "" {
		klog.ErrorS(nil, "Cloudsmith API returned error", "error", cloudsmithResponse.Error)
		return "", fmt.Errorf("Cloudsmith API returned error: %s", cloudsmithResponse.Error)
	}

	if cloudsmithResponse.Token == "" {
		klog.ErrorS(nil, "Received empty token from Cloudsmith API")
		return "", fmt.Errorf("received empty token from Cloudsmith API")
	}

	klog.InfoS("Successfully received token from Cloudsmith", "tokenLength", len(cloudsmithResponse.Token))
	return cloudsmithResponse.Token, nil
}

func parseTokenExpiration(tokenStr string) (time.Time, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, fmt.Errorf("failed to get JWT claims")
	}

	exp, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("JWT token missing exp claim")
	}

	var expFloat float64
	switch v := exp.(type) {
	case float64:
		expFloat = v
	case json.Number:
		expFloat, err = v.Float64()
		if err != nil {
			return time.Time{}, fmt.Errorf("failed to parse exp claim: %w", err)
		}
	default:
		return time.Time{}, fmt.Errorf("unexpected exp claim type: %T", exp)
	}

	expTime := time.Unix(int64(expFloat), 0)
	return expTime, nil
}

func (c *CloudsmithCredentialProvider) GetCredentials(ctx context.Context, req *credentialproviderapi.CredentialProviderRequest) (*credentialproviderapi.CredentialProviderResponse, error) {
	image := req.Image

	klog.InfoS("Processing credential request", "image", image)

	var oidcToken string
	var err error

	if req.ServiceAccountToken == "" {
		klog.ErrorS(nil, "Service account token is required but not provided")
		return nil, fmt.Errorf("service account token is required but not provided")
	}

	oidcToken = req.ServiceAccountToken
	c.overrideFromAnnotations(req.ServiceAccountAnnotations)

	if c.config.ServiceSlug == "" {
		klog.ErrorS(nil, "Service slug is required but not configured")
		return nil, fmt.Errorf("service_slug is required")
	}

	if c.config.OrgSlug == "" {
		klog.ErrorS(nil, "Organization slug is required but not configured")
		return nil, fmt.Errorf("org_slug is required")
	}

	cloudsmithToken, err := c.exchangeTokenWithCloudsmith(ctx, oidcToken)
	if err != nil {
		klog.ErrorS(err, "Failed to exchange token with Cloudsmith")
		return nil, fmt.Errorf("failed to exchange token with Cloudsmith: %w", err)
	}

	parts := strings.Split(image, "/")
	if len(parts) == 0 {
		klog.ErrorS(nil, "Invalid image format", "image", image)
		return nil, fmt.Errorf("invalid image format: %s", image)
	}
	registryHost := parts[0]

	klog.InfoS("Returning credentials for Cloudsmith registry",
		"registryHost", registryHost,
		"image", image)

	authConfig := credentialproviderapi.AuthConfig{
		Username: "token", // Cloudsmith uses "token" as username for token-based auth
		Password: cloudsmithToken,
	}

	expTime, err := parseTokenExpiration(cloudsmithToken)
	if err != nil {
		klog.V(4).InfoS("Failed to parse token expiration, using default cache duration", "error", err)
		expTime = time.Now().Add(1 * time.Hour)
	}

	now := time.Now()
	timeUntilExp := expTime.Sub(now)
	safetyMargin := timeUntilExp / 10
	cacheDuration := (timeUntilExp - safetyMargin).Truncate(time.Hour)

	klog.V(4).InfoS("Calculated cache duration",
		"tokenExpiration", expTime,
		"timeUntilExpiration", timeUntilExp,
		"safetyMargin", safetyMargin,
		"cacheDuration", cacheDuration)

	return &credentialproviderapi.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType:  credentialproviderapi.ImagePluginCacheKeyType,
		CacheDuration: &metav1.Duration{Duration: cacheDuration},
		Auth: map[string]credentialproviderapi.AuthConfig{
			registryHost: authConfig,
		},
	}, nil
}

func (c *CloudsmithCredentialProvider) overrideFromAnnotations(annotations map[string]string) {
	if annotations == nil {
		return
	}

	originalServiceSlug := c.config.ServiceSlug
	originalOrgSlug := c.config.OrgSlug
	originalAPIHost := c.config.APIHost

	if serviceSlug, exists := annotations["cloudsmith.io/service-slug"]; exists && serviceSlug != "" {
		c.config.ServiceSlug = serviceSlug
		klog.InfoS("Overrode service slug from annotation", "serviceSlug", serviceSlug)
	}

	if orgSlug, exists := annotations["cloudsmith.io/org-slug"]; exists && orgSlug != "" {
		c.config.OrgSlug = orgSlug
		klog.InfoS("Overrode org slug from annotation", "orgSlug", orgSlug)
	}

	if apiHost, exists := annotations["cloudsmith.io/api-host"]; exists && apiHost != "" {
		c.config.APIHost = apiHost
		klog.InfoS("Overrode API host from annotation", "apiHost", apiHost)
	}

	klog.V(4).InfoS("Configuration override summary",
		"originalServiceSlug", originalServiceSlug,
		"newServiceSlug", c.config.ServiceSlug,
		"originalOrgSlug", originalOrgSlug,
		"newOrgSlug", c.config.OrgSlug,
		"originalAPIHost", originalAPIHost,
		"newAPIHost", c.config.APIHost)
}

func setupLogging(logLevel string) {
	logs.InitLogs()

	var verbosity int
	switch strings.ToLower(logLevel) {
	case "debug":
		verbosity = 4
	case "info":
		verbosity = 2
	case "warn", "warning":
		verbosity = 1
	case "error":
		verbosity = 0
	default:
		verbosity = 2
	}

	klog.SetOutput(os.Stderr)
	if err := klog.V(klog.Level(verbosity)).Enabled(); err {
		klog.InfoS("Setting log verbosity", "level", verbosity)
	}

	klog.InfoS("Cloudsmith credential provider starting",
		"version", version,
		"commit", commit,
		"date", date,
		"logLevel", logLevel,
		"verbosity", verbosity)
}

func main() {
	flags := NewCommandFlags()

	var rootCmd = &cobra.Command{
		Use:     "cloudsmith-kubernetes-credential-provider",
		Short:   "Kubernetes credential provider for Cloudsmith registries",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(flags.ConfigFile)
			if err != nil {
				klog.ErrorS(err, "Failed to load configuration")
				return err
			}

			setupLogging(cfg.LogLevel)
			defer logs.FlushLogs()

			klog.InfoS("Starting credential provider request processing")

			provider := NewCloudsmithCredentialProvider(cfg)

			var req credentialproviderapi.CredentialProviderRequest
			if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
				klog.ErrorS(err, "Failed to decode credential provider request")
				errorResponse := &credentialproviderapi.CredentialProviderResponse{
					TypeMeta: metav1.TypeMeta{
						APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
						Kind:       "CredentialProviderResponse",
					},
					CacheKeyType:  credentialproviderapi.RegistryPluginCacheKeyType,
					CacheDuration: &metav1.Duration{Duration: 0},
					Auth:          map[string]credentialproviderapi.AuthConfig{},
				}
				if encErr := json.NewEncoder(os.Stdout).Encode(errorResponse); encErr != nil {
					klog.ErrorS(encErr, "Failed to encode error response")
				}
				return err
			}

			klog.InfoS("Received credential provider request",
				"image", req.Image,
				"hasServiceAccountToken", req.ServiceAccountToken != "",
				"annotationCount", len(req.ServiceAccountAnnotations))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			response, err := provider.GetCredentials(ctx, &req)
			if err != nil {
				klog.ErrorS(err, "Failed to get credentials")
				errorResponse := &credentialproviderapi.CredentialProviderResponse{
					TypeMeta: metav1.TypeMeta{
						APIVersion: credentialproviderapi.SchemeGroupVersion.String(),
						Kind:       "CredentialProviderResponse",
					},
					CacheKeyType:  credentialproviderapi.RegistryPluginCacheKeyType,
					CacheDuration: &metav1.Duration{Duration: 0},
					Auth:          map[string]credentialproviderapi.AuthConfig{},
				}
				if encErr := json.NewEncoder(os.Stdout).Encode(errorResponse); encErr != nil {
					klog.ErrorS(encErr, "Failed to encode error response")
				}
				return err
			}

			klog.InfoS("Successfully generated credential response",
				"authCount", len(response.Auth),
				"cacheKeyType", response.CacheKeyType,
				"cacheDuration", response.CacheDuration.Duration)

			if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
				klog.ErrorS(err, "Failed to encode credential response")
				return err
			}

			klog.InfoS("Credential provider request completed successfully")
			return nil
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := LoadConfig(flags.ConfigFile)
			if err != nil {
				klog.ErrorS(err, "Failed to load configuration")
				return
			}
			setupLogging(cfg.LogLevel)
			defer logs.FlushLogs()
			klog.InfoS("Version information",
				"version", version,
				"commit", commit,
				"built", date)
		},
	}

	rootCmd.PersistentFlags().StringVar(&flags.ConfigFile, "config", "", "Path to configuration file")

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		klog.ErrorS(err, "Command execution failed")
		logs.FlushLogs()
		os.Exit(1)
	}
}

type CommandFlags struct {
	ConfigFile string
}

func NewCommandFlags() *CommandFlags {
	return &CommandFlags{}
}

type Config struct {
	APIHost            string            `mapstructure:"api_host"`
	ServiceSlug        string            `mapstructure:"service_slug"`
	OrgSlug            string            `mapstructure:"org_slug"`
	LogLevel           string            `mapstructure:"log_level"`
	InsecureSkipVerify bool              `mapstructure:"insecure_skip_verify"`
	Headers            map[string]string `mapstructure:"headers"`

	HTTPTimeout     time.Duration `mapstructure:"http_timeout"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout"`

	MaxRetryAttempts     int           `mapstructure:"max_retry_attempts"`
	RetryBackoffDuration time.Duration `mapstructure:"retry_backoff_duration"`
	RetryBackoffFactor   float64       `mapstructure:"retry_backoff_factor"`
	RetryBackoffJitter   float64       `mapstructure:"retry_backoff_jitter"`
	RetryBackoffCap      time.Duration `mapstructure:"retry_backoff_cap"`
}

const (
	defaultConfigName = "cloudsmith-kubernetes-credential-provider"
	envPrefix         = "CLOUDSMITH"
)

func LoadConfig(configFile string) (*Config, error) {
	v := viper.NewWithOptions(viper.ExperimentalBindStruct())

	v.SetDefault("api_host", "api.cloudsmith.io")
	v.SetDefault("log_level", "info")
	v.SetDefault("insecure_skip_verify", false)
	v.SetDefault("headers", map[string]string{})

	v.SetDefault("http_timeout", 30*time.Second)
	v.SetDefault("max_idle_conns", 10)
	v.SetDefault("idle_conn_timeout", 30*time.Second)

	v.SetDefault("max_retry_attempts", 3)
	v.SetDefault("retry_backoff_duration", 1*time.Second)
	v.SetDefault("retry_backoff_factor", 2.0)
	v.SetDefault("retry_backoff_jitter", 0.1)
	v.SetDefault("retry_backoff_cap", 30*time.Second)

	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}
		klog.InfoS("Loaded configuration from file", "configFile", configFile)
	} else {
		// Try to read config from default locations, but don't fail if not found
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		} else {
			klog.InfoS("Loaded configuration from file", "configFile", v.ConfigFileUsed())
		}
	}

	headers := v.GetStringMapString("headers")
	if headers == nil {
		headers = make(map[string]string)
	}
	for _, env := range v.AllKeys() {
		if strings.HasPrefix(env, "header_") {
			headerName := strings.TrimPrefix(env, "header_")
			headerName = strings.ReplaceAll(headerName, "_", "-")
			headers[headerName] = v.GetString(env)
		}
	}
	v.Set("headers", headers)

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
