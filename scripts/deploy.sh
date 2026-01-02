#!/bin/bash

# Simplified Bedrock Security Config Rules Deployment Script

set -e

# Cleanup function for error handling
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo ""
        echo "🧹 Cleaning up temporary files..."
rm -rf temp_lambda_packages packaged-template.yaml 2>/dev/null || true
        echo "💥 Script exited with error code: $exit_code"
    fi
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Default values
STACK_NAME="bedrock-security-configrules-pack"
TEMPLATE_FILE="main-template.yaml"
TEMPLATES_BUCKET=""
OPERATION="deploy"
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
PROFILE=""
PACKAGE_ALL_CONTROLS=false







show_help() {
    echo "🚀 Bedrock Security Config Rules Pack Deployment"
    echo "Usage: $0 --bucket BUCKET_NAME [OPTIONS]"
    echo ""
    echo "📋 Required:"
    echo "  --bucket NAME           S3 bucket for templates (required)"
    echo ""
    echo "⚙️  Options:"
    echo "  --stack-name NAME       CloudFormation stack name (default: $STACK_NAME)"
    echo "  --region REGION         AWS region (default: $REGION)"
    echo "  --profile PROFILE       AWS profile to use"
    echo "  --update                Update existing stack"
    echo "  --package-all           Package all controls (ignore enabled/disabled status)"
    echo "  --help                  Show this help"
    echo ""
    echo "💡 Examples:"
    echo "  $0 --bucket my-templates-bucket"
    echo "  $0 --bucket my-templates-bucket --profile production --region us-west-2"
    echo "  $0 --bucket my-templates-bucket --package-all"
    echo ""
    echo "🔧 Automatic Setup:"
    echo "   • SSM parameters stack will be deployed automatically if not present"
    echo "   • S3 bucket will be created if it doesn't exist"
    echo "   • Only enabled controls are packaged (use --package-all to override)"
    echo "   • Configuration is managed through SSM Parameter Store"
    echo ""
    echo "📚 Manual SSM Parameters Deployment (if needed):"
    echo "   aws cloudformation deploy --template-file parameters/ssm-parameters.yaml --stack-name bedrock-security-ssm-parameters"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --bucket)
            TEMPLATES_BUCKET="$2"
            shift 2
            ;;
        --stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --update)
            OPERATION="update"
            shift
            ;;
        --package-all)
            PACKAGE_ALL_CONTROLS=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "❌ Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done



# Validate required parameters
if [ -z "$TEMPLATES_BUCKET" ]; then
    echo "❌ Error: --bucket is required"
    show_help
    exit 1
fi



if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "❌ Error: Template file '$TEMPLATE_FILE' not found"
    exit 1
fi



# Show banner
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                    🛡️  BEDROCK SECURITY CONFIG RULES PACK   🚀                 ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "🎯 === Deployment Summary ==="
echo "📚 Stack: $STACK_NAME"
echo "🌍 Region: $REGION"
echo "🪣 Bucket: $TEMPLATES_BUCKET"
echo "📦 Packaging: $([ "$PACKAGE_ALL_CONTROLS" = true ] && echo "All controls" || echo "Enabled controls only")"
echo "⚙️  Configuration: Parameter Store"
echo "============================="
echo ""

# Build AWS CLI profile parameter
PROFILE_PARAM=""
if [ ! -z "$PROFILE" ]; then
    PROFILE_PARAM="--profile $PROFILE"
fi

# Function to validate prerequisites
validate_prerequisites() {
    echo "🔍 Validating deployment prerequisites..."
    
    # Check AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        echo "❌ Error: AWS CLI is not installed or not in PATH"
        echo "❌ Error: AWS CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check AWS credentials are configured
    if ! aws sts get-caller-identity $PROFILE_PARAM --region "$REGION" >/dev/null 2>&1; then
        echo "❌ Error: AWS credentials not configured or invalid"
        echo "💡 Please configure AWS credentials using:"
        echo "   aws configure"
        if [ ! -z "$PROFILE" ]; then
            echo "   or: aws configure --profile $PROFILE"
        fi
        exit 1
    fi
    
    # Get and display caller identity
    CALLER_IDENTITY=$(aws sts get-caller-identity $PROFILE_PARAM --region "$REGION" --output text --query 'Account')
    echo "✅ AWS credentials validated (Account: $CALLER_IDENTITY)"
    
    # Check required files exist
    local required_files=("$TEMPLATE_FILE" "parameters/ssm-parameters.yaml")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            echo "❌ Error: Required file '$file' not found"
            exit 1
        fi
    done
    echo "✅ Required template files found"
    
    # Check if controls directory exists
    if [ ! -d "controls" ]; then
        echo "❌ Error: 'controls' directory not found"
        echo "💡 Please run this script from the root directory of the project"
        exit 1
    fi
    echo "✅ Controls directory found"
    
    echo "✅ All prerequisites validated successfully"
}

# Validate prerequisites before proceeding
validate_prerequisites

# Check and deploy SSM parameters stack if needed
SSM_STACK_NAME="bedrock-security-ssm-parameters"
echo "🔍 Checking if SSM parameters stack exists: $SSM_STACK_NAME"

# Check if SSM parameters stack exists
if ! aws cloudformation describe-stacks --stack-name "$SSM_STACK_NAME" --region "$REGION" $PROFILE_PARAM >/dev/null 2>&1; then
    echo "📋 SSM parameters stack not found. Deploying SSM parameters stack..."
    
    # Check if SSM parameters template exists
    if [ ! -f "parameters/ssm-parameters.yaml" ]; then
        echo "❌ Error: SSM parameters template 'parameters/ssm-parameters.yaml' not found"
        echo "💡 This file is required to create the SSM parameters for configuration"
        exit 1
    fi
    
    # Deploy SSM parameters stack
    echo "🚀 Deploying SSM parameters stack..."
    if aws cloudformation deploy \
        --stack-name "$SSM_STACK_NAME" \
        --template-file "parameters/ssm-parameters.yaml" \
        --region "$REGION" \
        $PROFILE_PARAM; then
        echo "✅ SSM parameters stack deployed successfully"
    else
        echo "❌ Error: Failed to deploy SSM parameters stack"
        echo "💡 Please check the CloudFormation console for details:"
        echo "🔗 Console: https://$REGION.console.aws.amazon.com/cloudformation/home?region=$REGION"
        exit 1
    fi
else
    echo "✅ SSM parameters stack already exists: $SSM_STACK_NAME"
fi

# Create bucket if it doesn't exist
echo "🪣 Checking S3 bucket: $TEMPLATES_BUCKET"
if ! aws s3api head-bucket --bucket "$TEMPLATES_BUCKET" --region "$REGION" $PROFILE_PARAM 2>/dev/null; then
    echo "🆕 Creating bucket: $TEMPLATES_BUCKET"
    
    # Create bucket with proper region configuration
    if [ "$REGION" = "us-east-1" ]; then
        if aws s3api create-bucket --bucket "$TEMPLATES_BUCKET" $PROFILE_PARAM; then
            echo "✅ Bucket created successfully: $TEMPLATES_BUCKET"
        else
            echo "❌ Error: Failed to create S3 bucket: $TEMPLATES_BUCKET"
            echo "💡 This could be due to:"
            echo "   - Bucket name already exists globally"
            echo "   - Insufficient IAM permissions (s3:CreateBucket)"
            echo "   - Invalid bucket name format"
            exit 1
        fi
    else
        if aws s3api create-bucket \
            --bucket "$TEMPLATES_BUCKET" \
            --region "$REGION" \
            --create-bucket-configuration LocationConstraint="$REGION" \
            $PROFILE_PARAM; then
            echo "✅ Bucket created successfully: $TEMPLATES_BUCKET"
        else
            echo "❌ Error: Failed to create S3 bucket: $TEMPLATES_BUCKET"
            echo "💡 This could be due to:"
            echo "   - Bucket name already exists globally"
            echo "   - Insufficient IAM permissions (s3:CreateBucket)"
            echo "   - Invalid bucket name format"
            echo "   - Region-specific issues"
            exit 1
        fi
    fi
    
    # Enable versioning on the bucket for better template management
    echo "🔄 Enabling versioning on bucket: $TEMPLATES_BUCKET"
    if aws s3api put-bucket-versioning \
        --bucket "$TEMPLATES_BUCKET" \
        --versioning-configuration Status=Enabled \
        $PROFILE_PARAM; then
        echo "✅ Versioning enabled on bucket"
    else
        echo "⚠️  Warning: Failed to enable versioning on bucket (continuing anyway)"
    fi
    
else
    echo "✅ Bucket exists: $TEMPLATES_BUCKET"
fi

# Update SSM parameter with the provided bucket name
echo "⚙️  Updating SSM parameter with bucket name: $TEMPLATES_BUCKET"
if ! aws ssm put-parameter \
    --name "/bedrock-configrules/global/TemplatesBucketName" \
    --value "$TEMPLATES_BUCKET" \
    --type "String" \
    --overwrite \
    --region "$REGION" \
    $PROFILE_PARAM; then
    echo "❌ Error: Failed to update SSM parameter '/bedrock-configrules/global/TemplatesBucketName'"
    echo "💡 This could be due to:"
    echo "   - Insufficient IAM permissions for SSM operations"
    echo "   - The SSM parameters stack may not have been deployed properly"
    echo "   - Network connectivity issues"
    echo "   - Invalid AWS credentials or profile"
    echo "   - Region mismatch"
    echo ""
    echo "🔧 Please ensure you have the following IAM permissions:"
    echo "   - ssm:PutParameter"
    echo "   - ssm:GetParameter (for verification)"
    echo "   - cloudformation:DescribeStacks"
    echo "   - cloudformation:CreateStack"
    echo "   - cloudformation:UpdateStack"
    echo ""
    echo "🔍 You can also manually deploy the SSM parameters stack with:"
    echo "   aws cloudformation deploy --template-file parameters/ssm-parameters.yaml --stack-name $SSM_STACK_NAME --region $REGION"
    echo ""
    exit 1
fi

echo "✅ SSM parameter updated successfully"

# Function to get enabled controls from SSM Parameter Store
get_enabled_controls() {
    local all_controls=(FMI-03 FMI-01 FMI-04 FMI-05 FMI-06 FMI-07 FMI-08 FMI-09 FMI-10 FMI-02 FMI-17 FMI-18 FMI-19 FMI-11 FMI-12 FMI-13 FMI-14 FMI-15 FMI-16 RAG-01 RAG-02)
    
    # If --package-all flag is set, return all controls
    if [ "$PACKAGE_ALL_CONTROLS" = true ]; then
        echo "📦 --package-all flag detected. Packaging all available controls..." >&2
        echo "${all_controls[@]}"
        return
    fi
    
    echo "🔍 Checking which controls are enabled in SSM Parameter Store..." >&2
    
    local enabled_controls=()
    
    for control in "${all_controls[@]}"; do
        # Convert control ID to parameter name (e.g., FMI-03 -> DeployFMI01)
        param_name=$(echo "$control" | sed 's/-//g')
        param_path="/bedrock-configrules/global/Deploy${param_name}"
        
        # Check if control is enabled
        if enabled_value=$(aws ssm get-parameter --name "$param_path" --region "$REGION" $PROFILE_PARAM --query 'Parameter.Value' --output text 2>/dev/null); then
            if [[ "$enabled_value" == "true" ]]; then
                enabled_controls+=("$control")
                echo "  ✅ $control: enabled" >&2
            else
                echo "  ⏸️  $control: disabled" >&2
            fi
        else
            echo "  ❓ $control: parameter not found (assuming disabled)" >&2
        fi
    done
    
    if [ ${#enabled_controls[@]} -eq 0 ]; then
        echo "⚠️  Warning: No controls are enabled. Packaging all controls as fallback." >&2
        enabled_controls=("${all_controls[@]}")
    else
        echo "📊 Found ${#enabled_controls[@]} enabled controls: ${enabled_controls[*]}" >&2
        
        # Show which controls are being skipped
        local disabled_controls=()
        for control in "${all_controls[@]}"; do
            if [[ ! " ${enabled_controls[*]} " =~ " ${control} " ]]; then
                disabled_controls+=("$control")
            fi
        done
        
        if [ ${#disabled_controls[@]} -gt 0 ]; then
            echo "⏭️  Skipping ${#disabled_controls[@]} disabled controls: ${disabled_controls[*]}" >&2
        fi
    fi
    
    # Return enabled controls as a space-separated string
    echo "${enabled_controls[@]}"
}

# Get enabled controls from SSM Parameter Store
echo "🔍 Determining which controls to package..."
ENABLED_CONTROLS_OUTPUT=$(get_enabled_controls)
if [ $? -eq 0 ] && [ -n "$ENABLED_CONTROLS_OUTPUT" ]; then
    ENABLED_CONTROLS=($ENABLED_CONTROLS_OUTPUT)
else
    echo "❌ Error: Failed to determine enabled controls"
    echo "💡 This could be due to:"
    echo "   - SSM parameters stack not deployed yet"
    echo "   - Insufficient IAM permissions for SSM operations"
    echo "   - Network connectivity issues"
    echo ""
    echo "🔧 Falling back to packaging all controls..."
    PACKAGE_ALL_CONTROLS=true
    ENABLED_CONTROLS=(FMI-03 FMI-01 FMI-04 FMI-05 FMI-06 FMI-07 FMI-08 FMI-09 FMI-10 FMI-02 FMI-17 FMI-18 FMI-19 FMI-11 FMI-12 FMI-13 FMI-14 FMI-15 FMI-16 RAG-01 RAG-02)
fi

# Package Lambda functions for enabled controls only
echo "📦 Packaging Lambda functions for ${#ENABLED_CONTROLS[@]} enabled controls..."
echo "🔍 Available control directories:"
ls -1 controls/ | grep -E '^(fmi|rag)-[0-9]' | sed 's/^/  /'
echo ""
mkdir -p temp_lambda_packages

# Convert control IDs to directory names and package only enabled controls
for control in "${ENABLED_CONTROLS[@]}"; do
    control=$(echo "$control" | xargs) # trim whitespace
    # Convert control ID to directory name (e.g., FMI-05 -> fmi-05-model-invocation-logging)
    control_lower=$(echo "$control" | tr '[:upper:]' '[:lower:]')
    
    # Find matching control directory
    control_dir=$(find controls -maxdepth 1 -type d -name "${control_lower}-*" | head -1)
    
    if [ -n "$control_dir" ] && [ -d "$control_dir" ]; then
        echo "  🎯 Processing enabled control: $control ($control_dir)"
        
        # Package lambda functions in this control directory
        find "$control_dir" -name "*.py" -type f | while read -r lambda_file; do
            dir_name=$(basename "$control_dir")
            base_name=$(basename "$lambda_file" .py)
            
            # Create correct zip name based on function type
            if [[ "$base_name" == "lambda-function" ]]; then
                zip_name="${dir_name}-check.zip"
            elif [[ "$base_name" == "remediation-lambda-function" ]]; then
                zip_name="${dir_name}-remediation.zip"
            else
                zip_name="${dir_name}-${base_name}.zip"
            fi
            
            echo "    📄 Packaging: $zip_name"
            # Change to the directory containing the lambda file to avoid including path in zip
            (cd "$(dirname "$lambda_file")" && zip -q "../../temp_lambda_packages/$zip_name" "$(basename "$lambda_file")")
        done
    else
        echo "  ⚠️  Warning: Control directory not found for $control (expected: ${control_lower}-*)"
    fi
done

# Upload Lambda packages
echo "☁️  Uploading Lambda packages to S3..."
aws s3 sync temp_lambda_packages/ "s3://$TEMPLATES_BUCKET/lambda-functions/" --region "$REGION" $PROFILE_PARAM

# Clean up
echo "🧹 Cleaning up temporary files..."
rm -rf temp_lambda_packages

# Package CloudFormation template
echo "📋 Packaging CloudFormation template..."
aws cloudformation package \
    --template-file "$TEMPLATE_FILE" \
    --s3-bucket "$TEMPLATES_BUCKET" \
    --s3-prefix "controls" \
    --output-template-file "packaged-template.yaml" \
    --region "$REGION" \
    $PROFILE_PARAM

# Configuration managed through SSM Parameter Store
echo "⚙️  Reading configuration from SSM Parameter Store"

# Deploy stack
echo "🚀 Deploying CloudFormation stack..."
aws cloudformation deploy \
    --stack-name "$STACK_NAME" \
    --template-file "packaged-template.yaml" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$REGION" \
    $PROFILE_PARAM

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    🎉 DEPLOYMENT COMPLETED SUCCESSFULLY! ✅                   ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📋 Deployment Summary:"
    echo "   📚 Main Stack: $STACK_NAME"
    echo "   🔧 SSM Parameters Stack: $SSM_STACK_NAME"
    echo "   🌍 Region: $REGION"
    echo "   🪣 Templates Bucket: $TEMPLATES_BUCKET"
    echo "   📦 Controls Packaged: ${#ENABLED_CONTROLS[@]} ($([ "$PACKAGE_ALL_CONTROLS" = true ] && echo "all controls" || echo "enabled only"))"
    echo "   ⚙️  Configuration: SSM Parameter Store"
    echo ""
    echo "🔗 AWS Console Links:"
    echo "   📊 Main Stack: https://$REGION.console.aws.amazon.com/cloudformation/home?region=$REGION#/stacks/stackinfo?stackId=$STACK_NAME"
    echo "   🔧 SSM Parameters: https://$REGION.console.aws.amazon.com/cloudformation/home?region=$REGION#/stacks/stackinfo?stackId=$SSM_STACK_NAME"
    echo "   📈 Config Rules: https://$REGION.console.aws.amazon.com/config/home?region=$REGION#/rules"
    echo "   🪣 S3 Bucket: https://s3.console.aws.amazon.com/s3/buckets/$TEMPLATES_BUCKET"
    echo ""
    echo "🎯 Next Steps:"
    echo "   1. Review deployed Config rules in the AWS Config console"
    echo "   2. Customize rule parameters via SSM Parameter Store if needed"
    echo "   3. Monitor compliance status and remediation actions"
    echo "   4. Set up notifications for non-compliant resources"
    echo ""
    echo "📚 Documentation: Check the README.md for configuration details"
else
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        💥 DEPLOYMENT FAILED ❌                               ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🔍 Troubleshooting:"
    echo "   🔗 CloudFormation Console: https://$REGION.console.aws.amazon.com/cloudformation/home?region=$REGION"
    echo "   📋 Check stack events for detailed error messages"
    echo "   🔧 Verify IAM permissions for CloudFormation operations"
    echo "   📊 Review template syntax and parameter values"
    echo ""
    echo "💡 Common Issues:"
    echo "   • Insufficient IAM permissions"
    echo "   • Resource limits exceeded"
    echo "   • Invalid parameter values in SSM Parameter Store"
    echo "   • Network connectivity issues"
    echo ""
    exit 1
fi