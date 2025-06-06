⚠️ Alpha Release Notice

This project is in very early development and should be considered Alpha software. Expect significant changes, incomplete features, and potential breaking changes between releases.

# Cloudsmith Kubernetes Credential Provider

This credential provider enables Kubernetes to automatically authenticate with Cloudsmith registries using OIDC service account tokens. It implements the [Kubelet Credential Provider](https://kubernetes.io/docs/tasks/kubelet-credential-provider/kubelet-credential-provider/) interface, following [KEP-4412](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/4412-projected-service-account-tokens-for-kubelet-image-credential-providers/README.md) for supporting service account token authentication for image pulls.

## Features

- **Service Account Token Authentication**: Uses ephemeral Kubernetes service account tokens instead of long-lived static credentials
- **Dynamic Configuration**: Supports pod-level identity for image pulls with configurable service account annotations
- **Automatic Token Refresh**: Handles token lifecycle and caching automatically
- **Registry Pattern Matching**: Flexible image matching patterns for Cloudsmith registries
- **Security-First Design**: Eliminates the need for storing static secrets in the cluster

## How It Works

The credential provider works by:

1. **Token Generation**: Kubelet generates a service account token bound to the specific pod requesting image pull
2. **Plugin Invocation**: Kubelet calls the credential provider with the token and service account annotations
3. **Authentication Exchange**: Plugin exchanges the service account token with Cloudsmith for registry credentials
4. **Image Pull**: Kubelet uses the returned credentials to authenticate with the Cloudsmith registry

---

# Hands-on Walkthrough: Running with Minikube

**Learning Objectives**:
- Understand KEP-4412 service account token authentication
- Configure kubelet credential providers
- Set up OIDC token validation
- Test token-based image pulls

## Prerequisites Check

**Kubernetes 1.33 is required** for service account token authentication support.

**Verify everything is installed:**

**Open a third terminal and run:**

```bash
cd /tmp/k8s-example
```

```bash
docker --version
minikube version
kubectl version --client
python3 --version
ngrok --version
jq --version
```

**If ANY command fails, install that tool before continuing.**

---

## Setup Steps

### Step 1: Set Up Workspace

```bash
mkdir -p /tmp/k8s-example
```

### Step 2: Start Web Server (Terminal 1)

**Open a new terminal and run:**

```bash
cd /tmp/k8s-example
mkdir -p openid-metadata
cd openid-metadata
python3 -m http.server 8000
```

**Keep this terminal open - leave the server running.**

### Step 3: Start ngrok (Terminal 2)

**Open another new terminal and run:**

```bash
ngrok http 8000
```

**Keep this terminal open.**

### Step 4: Create Configuration Files (Terminal 3)

```bash
mkdir -p /tmp/k8s-example
```

```bash
cat > node-credential-providers.yaml << 'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-credential-providers
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get", "list"]
- verbs: ["request-serviceaccounts-token-audience"]
  apiGroups: [""]
  resources: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: node-serviceaccount-wide-access-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: node-credential-providers
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:node:minikube
EOF
```

```bash
cat > credential-provider-config.yaml << 'EOF'
apiVersion: kubelet.config.k8s.io/v1
kind: CredentialProviderConfig
providers:
  - name: cloudsmith-kubernetes-credential-provider
    matchImages:
      - "docker.cloudsmith.io"
    defaultCacheDuration: "1h"
    apiVersion: credentialprovider.kubelet.k8s.io/v1
    env:
      # These are cluster-wide defaults - can be overridden per service account
      # Remove these lines if you want to force per-service-account configuration
      - name: CLOUDSMITH_SERVICE_SLUG
        value: default-v9ty
      - name: CLOUDSMITH_ORG_SLUG
        value: iduffy-demo
    tokenAttributes:
      serviceAccountTokenAudience: "cloudsmith"
      requireServiceAccount: true
      optionalServiceAccountAnnotationKeys:
        - "cloudsmith.io/service-slug"
        - "cloudsmith.io/org-slug"
EOF
```

### Step 5: Start Minikube

```bash
export NGROK_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
```

```bash
minikube start \
  --kubernetes-version=v1.33.0 \
  --extra-config=kubelet.feature-gates="KubeletServiceAccountTokenForCredentialProviders=true" \
  --extra-config=kubelet.image-credential-provider-config="/etc/kubernetes/credential-provider-config.yaml" \
  --extra-config=kubelet.image-credential-provider-bin-dir="/usr/local/bin" \
  --extra-config=apiserver.service-account-issuer="$NGROK_URL"
```

### Step 6: Install the Plugin

Download the latest plugin from "https://github.com/cloudsmith-io/cloudsmith-kubernetes-credential-provider/releases" and extract it into `/tmp/k8s-example`

```bash
cd /tmp/k8s-example

# Copy the downloaded plugin to minikube
minikube cp "./cloudsmith-kubernetes-credential-provider" /usr/local/bin/cloudsmith-kubernetes-credential-provider
```

```bash
minikube ssh "sudo chmod 755 /usr/local/bin/cloudsmith-kubernetes-credential-provider"
```

### Step 8: Configure Kubernetes

```bash
cd /tmp/k8s-example
```

```bash
minikube cp credential-provider-config.yaml /etc/kubernetes/
```

```bash
kubectl apply -f node-credential-providers.yaml
```

### Step 9: Set Up OIDC Metadata

```bash
cd openid-metadata
mkdir -p .well-known
```

```bash
kubectl get --raw /.well-known/openid-configuration > .well-known/openid-configuration
kubectl get --raw /openid/v1/jwks > jwks.json
```

```bash
export NGROK_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
```

```bash
jq --arg jwks_url "$NGROK_URL/jwks.json" '.jwks_uri = $jwks_url' .well-known/openid-configuration > temp.json && mv temp.json .well-known/openid-configuration
```

### Step 10: Configure OIDC on Cloudsmith

Configure your OIDC on cloudsmith as you see fit using the $NGROK_URL as your provider URL.

### Step 11: Test the Setup

```bash
cd /tmp/k8s-example
```

```bash
cat > test-pod.yaml << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-service-account
  annotations:
    # This overrides the cluster-wide default CLOUDSMITH_SERVICE_SLUG
    "cloudsmith.io/service-slug": "purple-team-sa"
---
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu-pod
spec:
  serviceAccountName: my-service-account
  containers:
  - name: ubuntu-container
    image: docker.cloudsmith.io/iduffy-demo/purple-team/ubuntu:latest
    imagePullPolicy: Always
    command: ["sleep"]
    args: ["infinity"]
EOF
```

```bash
kubectl apply -f test-pod.yaml
```

```bash
kubectl get pods
```

```bash
kubectl describe pod ubuntu-pod
```

**Look for events showing the credential provider was called and image pull attempted.**

### Step 12: Cleanup

```bash
kubectl delete -f test-pod.yaml
minikube stop && minikube delete
```

**In Terminal 1 (web server): Press Ctrl+C**
**In Terminal 2 (ngrok): Press Ctrl+C**

```bash
rm -rf /tmp/k8s-example
```

---

## What You Accomplished

- Set up a local Kubernetes environment with Minikube
- Configured KEP-4412 service account token authentication
- Set up OIDC token validation with ngrok
- Tested pod-level authentication for image pulls
