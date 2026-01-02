# FMI-04: Model Invocation Logging Enforcement - Testing Guide

## Overview
FMI-04 (Model Invocation Logging Enforcement) ensures that all Bedrock model invocations are logged for audit and monitoring purposes. This control verifies that model invocation logging is enabled in Amazon Bedrock configuration with appropriate storage destinations.

This document helps you understand how the FMI-04 control evaluates the account-level Bedrock logging configuration.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to configure Bedrock logging settings
- AWS Config enabled and the FMI-04 control deployed
- S3 bucket or CloudWatch log group for log storage (if testing remediation)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-04" --recursive
```



## Test Setup

### 1. Check Current Bedrock Logging Configuration
```bash
# Check current model invocation logging configuration
aws bedrock get-model-invocation-logging-configuration

# Expected output if logging is disabled:
# {
#     "loggingConfig": null
# }
```

### 2. Create Test S3 Bucket for Logging (Optional)
```bash
# Create S3 bucket for Bedrock logs (if testing S3 destination)
BUCKET_NAME="bedrock-logs-test-$(date +%s)"
aws s3 mb s3://$BUCKET_NAME --region us-east-1

# Enable versioning and encryption
aws s3api put-bucket-versioning \
  --bucket $BUCKET_NAME \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket $BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }
    ]
  }'
```

### 3. Create Test CloudWatch Log Group (Optional)
```bash
# Create CloudWatch log group for Bedrock logs (if testing CloudWatch destination)
LOG_GROUP_NAME="/aws/bedrock/modelinvocations-test"
aws logs create-log-group --log-group-name $LOG_GROUP_NAME

# Set retention policy
aws logs put-retention-policy \
  --log-group-name $LOG_GROUP_NAME \
  --retention-in-days 90
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation (Non-Compliant State)
With logging disabled, trigger the Config rule to evaluate the account:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-04-model-invocation-logging
```

### 2. Check Evaluation Results
View the compliance status:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-04-model-invocation-logging
```

### 3. Expected Results (Before Enabling Logging)

**Account with Logging Disabled:**
- **Status:** NON_COMPLIANT
- **Reason:** Model invocation logging is not enabled in Amazon Bedrock

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
```bash
# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-04-model-invocation-logging \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-04-model-invocation-logging
```

### 3. Verify Remediation Results
Check if model invocation logging was enabled:

```bash
# Verify logging configuration was created
aws bedrock get-model-invocation-logging-configuration
```

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-04-model-invocation-logging
```

### 5. Expected Results (After Automatic Remediation)

**Account with Logging Enabled:**
- **Status:** COMPLIANT
- **Reason:** Model invocation logging is properly configured with required destinations

## Verify Logging Configuration
```bash
# Verify logging configuration was created by remediation
aws bedrock get-model-invocation-logging-configuration
```

## Cleanup Test Resources
```bash
# Get log group name before disabling logging
LOG_GROUP_NAME=$(aws bedrock get-model-invocation-logging-configuration --query 'loggingConfig.cloudWatchConfig.logGroupName' --output text)

# Disable model invocation logging
aws bedrock delete-model-invocation-logging-configuration

# Delete CloudWatch log group if it exists
if [ "$LOG_GROUP_NAME" != "None" ] && [ "$LOG_GROUP_NAME" != "null" ]; then
  aws logs delete-log-group --log-group-name $LOG_GROUP_NAME
  echo "Deleted Cloudwatch Logs $LOG_GROUP_NAME"
else
  echo "No CloudWatch log group configured for cleanup"
fi

# Delete test S3 bucket (empty it first)
aws s3 rm s3://$BUCKET_NAME --recursive
aws s3 rb s3://$BUCKET_NAME

# Delete IAM role and policy
aws iam delete-role-policy \
  --role-name AmazonBedrockExecutionRoleForModelInvocationLogging \
  --policy-name BedrockLoggingPolicy

aws iam delete-role --role-name AmazonBedrockExecutionRoleForModelInvocationLogging

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-04-model-invocation-logging`

