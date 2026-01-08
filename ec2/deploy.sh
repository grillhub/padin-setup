#!/bin/bash

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check required environment variables
check_env_var() {
    if [ -z "${!1}" ]; then
        log_error "Missing required environment variable: $1"
        exit 1
    fi
}

log_info "Starting deployment process..."

# Check required environment variables
check_env_var "WEBSITE_BUCKET_NAME"
check_env_var "ZIP_URL"
check_env_var "LAMBDA_FUNCTION_URL"
check_env_var "ADMIN_REGISTRATION_FUNCTION_NAME"
check_env_var "GITHUB_CODE_URL"
check_env_var "EC2_MANAGEMENT_FUNCTION_NAME"
check_env_var "EC2_MANAGEMENT_GITHUB_URL"

# Function to deploy website to S3
deploy_website() {
    log_info "Deploying website to S3 bucket: $WEBSITE_BUCKET_NAME"
    
    local zip_file="/tmp/website.zip"
    local extract_dir="/tmp/website_extract"
    
    # Download ZIP file
    log_info "Downloading ZIP file from: $ZIP_URL"
    if ! curl -fsSL "$ZIP_URL" -o "$zip_file"; then
        log_error "Failed to download ZIP file from $ZIP_URL"
        return 1
    fi
    
    local zip_size=$(stat -c%s "$zip_file" 2>/dev/null || wc -c < "$zip_file" 2>/dev/null || echo "unknown")
    log_info "Downloaded ZIP file, size: $zip_size bytes"
    
    # Create extraction directory
    mkdir -p "$extract_dir"
    cd "$extract_dir"
    
    # Extract ZIP file
    log_info "Extracting ZIP file..."
    unzip -q "$zip_file" || {
        log_error "Failed to extract ZIP file"
        return 1
    }
    
    # Update endpoint.json if it exists
    if [ -f "endpoint.json" ]; then
        log_info "Updating endpoint.json with Lambda Function URL: $LAMBDA_FUNCTION_URL"
        if command -v jq &> /dev/null; then
            jq --arg url "$LAMBDA_FUNCTION_URL" '.API_BASE_URL = $url' endpoint.json > endpoint.json.tmp && mv endpoint.json.tmp endpoint.json
        else
            # Fallback: use sed if jq is not available
            sed -i.bak "s|\"API_BASE_URL\":[^,]*|\"API_BASE_URL\": \"$LAMBDA_FUNCTION_URL\"|" endpoint.json
        fi
    fi
    
    # Upload files to S3
    log_info "Uploading files to S3..."
    local file_count=0
    
    # Function to determine content type
    get_content_type() {
        local file="$1"
        case "$file" in
            *.html) echo "text/html" ;;
            *.css) echo "text/css" ;;
            *.js) echo "application/javascript" ;;
            *.png) echo "image/png" ;;
            *.jpg|*.jpeg) echo "image/jpeg" ;;
            *.gif) echo "image/gif" ;;
            *.svg) echo "image/svg+xml" ;;
            *.json) echo "application/json" ;;
            *) echo "application/octet-stream" ;;
        esac
    }
    
    # Upload all files
    for file in $(find . -type f); do
        local key="${file#./}"  # Remove leading ./
        local content_type=$(get_content_type "$key")
        
        if aws s3 cp "$file" "s3://$WEBSITE_BUCKET_NAME/$key" \
            --content-type "$content_type" \
            --quiet; then
            file_count=$((file_count + 1))
            log_info "Uploaded: $key"
        else
            log_error "Failed to upload $key"
            return 1
        fi
    done
    
    # Cleanup
    cd /
    rm -rf "$extract_dir" "$zip_file"
    
    log_info "Successfully deployed website with $file_count files"
    return 0
}

# Function to update Lambda function code from GitHub
update_lambda_function() {
    local function_name="$1"
    local github_url="$2"
    local description="$3"
    
    log_info "Updating $description: $function_name"
    
    local code_file="/tmp/lambda_code.py"
    local zip_file="/tmp/lambda_code.zip"
    
    # Download code from GitHub
    log_info "Downloading code from GitHub: $github_url"
    if ! curl -fsSL "$github_url" -o "$code_file"; then
        log_error "Failed to download code from GitHub: $github_url"
        return 1
    fi
    
    local code_size=$(stat -c%s "$code_file" 2>/dev/null || wc -c < "$code_file" 2>/dev/null || echo "unknown")
    log_info "Downloaded code from GitHub, size: $code_size bytes"
    
    # Create zip file with index.py (Lambda handler expects index.lambda_handler)
    log_info "Creating zip file..."
    cd /tmp
    mv "$code_file" index.py
    zip -q "$zip_file" index.py || {
        log_error "Failed to create zip file"
        return 1
    }
    
    local zip_size=$(stat -c%s "$zip_file" 2>/dev/null || wc -c < "$zip_file" 2>/dev/null || echo "unknown")
    log_info "Created zip file, size: $zip_size bytes"
    
    # Update Lambda function
    log_info "Updating Lambda function: $function_name"
    if aws lambda update-function-code \
        --function-name "$function_name" \
        --zip-file "fileb://$zip_file" \
        --output json > /tmp/lambda_update_response.json 2>&1; then
        
        local function_arn=$(jq -r '.FunctionArn' /tmp/lambda_update_response.json 2>/dev/null || echo "unknown")
        local last_modified=$(jq -r '.LastModified' /tmp/lambda_update_response.json 2>/dev/null || echo "unknown")
        
        log_info "Successfully updated Lambda function: $function_name"
        log_info "Function ARN: $function_arn"
        log_info "Last modified: $last_modified"
        
        # Cleanup
        rm -f index.py "$zip_file" /tmp/lambda_update_response.json
        
        return 0
    else
        local error=$(cat /tmp/lambda_update_response.json 2>/dev/null || echo "Unknown error")
        log_error "Failed to update Lambda function: $error"
        rm -f index.py "$zip_file" /tmp/lambda_update_response.json
        return 1
    fi
}

# Main deployment process
main() {
    log_info "=== Starting Deployment ==="
    
    # Deploy website
    if ! deploy_website; then
        log_error "Website deployment failed"
        exit 1
    fi
    
    # Update admin registration function
    if ! update_lambda_function \
        "$ADMIN_REGISTRATION_FUNCTION_NAME" \
        "$GITHUB_CODE_URL" \
        "admin registration function"; then
        log_warn "Failed to update admin registration function (continuing...)"
    fi
    
    # Update EC2 management function
    if ! update_lambda_function \
        "$EC2_MANAGEMENT_FUNCTION_NAME" \
        "$EC2_MANAGEMENT_GITHUB_URL" \
        "EC2 management function"; then
        log_warn "Failed to update EC2 management function (continuing...)"
    fi
    
    log_info "=== Deployment Complete ==="
}

# Run main function
main
