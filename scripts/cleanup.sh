#!/bin/bash

# Bedrock Security Config Rules Cleanup Script
# Deletes both the main stack and SSM parameters stack

set -e

MAIN_STACK="bedrock-security-configrules-pack"
SSM_STACK="bedrock-security-ssm-parameters"
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

show_help() {
    echo "Usage: $0 [--region REGION] [--profile PROFILE] [--help]"
    echo ""
    echo "Deletes Bedrock security stacks:"
    echo "  Main stack: $MAIN_STACK"
    echo "  SSM stack:  $SSM_STACK"
    echo ""
    echo "Options:"
    echo "  --region REGION    AWS region (default: $REGION)"
    echo "  --profile PROFILE  AWS profile to use"
    echo "  --help            Show this help"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Set AWS CLI options
AWS_OPTS="--region $REGION"
if [[ -n "$PROFILE" ]]; then
    AWS_OPTS="$AWS_OPTS --profile $PROFILE"
fi

echo "🧹 Bedrock Security Cleanup"
echo "Region: $REGION"
echo ""

# Confirm deletion
echo "⚠️  This will permanently delete all Bedrock security controls!"
read -p "Type 'yes' to confirm: " confirmation
if [[ "$confirmation" != "yes" ]]; then
    echo "Cleanup cancelled"
    exit 0
fi

# Delete main stack first
echo "Deleting main stack: $MAIN_STACK"
if aws cloudformation describe-stacks --stack-name "$MAIN_STACK" $AWS_OPTS >/dev/null 2>&1; then
    aws cloudformation delete-stack --stack-name "$MAIN_STACK" $AWS_OPTS
    echo "Waiting for main stack deletion..."
    aws cloudformation wait stack-delete-complete --stack-name "$MAIN_STACK" $AWS_OPTS
    echo "✅ Main stack deleted"
else
    echo "Main stack not found"
fi

# Delete SSM stack
echo "Deleting SSM stack: $SSM_STACK"
if aws cloudformation describe-stacks --stack-name "$SSM_STACK" $AWS_OPTS >/dev/null 2>&1; then
    aws cloudformation delete-stack --stack-name "$SSM_STACK" $AWS_OPTS
    echo "Waiting for SSM stack deletion..."
    aws cloudformation wait stack-delete-complete --stack-name "$SSM_STACK" $AWS_OPTS
    echo "✅ SSM stack deleted"
else
    echo "SSM stack not found"
fi

echo ""
echo "✅ Cleanup completed!"