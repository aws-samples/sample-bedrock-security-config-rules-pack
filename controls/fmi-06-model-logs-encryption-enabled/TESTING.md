# FMI-06: Model Logs KMS Encryption - Testing Guide

## Overview
FMI-06 (Model Logs KMS Encryption) ensures customer-managed KMS keys are used for encryption of Bedrock model invocation logs stored in CloudWatch Logs and S3. This control validates that sensitive model invocation data is properly encrypted at rest.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Model invocation logging enabled (FMI-04 must be compliant)
- Permissions to create/manage KMS keys
- AWS Config enabled and the FMI-06 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-06" --recursive
```




## Test Setup

### 1. Check Current Bedrock Logging Configuration
First, identify which logging destinations are configured for Bedrock model invocation logging:

```bash
# Check current Bedrock model invocation logging configuration
```bash
# Extract the specific values you'll need for the KMS policy
S3_BUCKET=$(aws bedrock get-model-invocation-logging-configuration --query 'loggingConfig.s3Config.bucketName' --output text 2>/dev/null)

CW_LOG_GROUP=$(aws bedrock get-model-invocation-logging-configuration --query 'loggingConfig.cloudWatchConfig.logGroupName' --output text 2>/dev/null)
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
REGION=$(aws configure get region)

echo "S3 Bucket: $S3_BUCKET"
echo "CloudWatch Log Group: $CW_LOG_GROUP"
echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
```

**Note these values** - you'll use them in the next step to customize the KMS policy.


**Important:** This control requires model invocation logging to be enabled (FMI-04). If no `loggingConfig` is present, enable logging first.

### 2. Create Customer-Managed KMS Key
```bash
# Create a customer-managed KMS key for testing
KEY_ID=$(aws kms create-key --description "Test key for Bedrock model logs" --query 'KeyMetadata.KeyId' --output text)
KEY_ARN=$(aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.Arn' --output text)
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
echo "Created KMS Key ID: $KEY_ID"
echo "KMS Key ARN: $KEY_ARN"

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/bedrock-logs-test \
  --target-key-id $KEY_ID

# Enable key rotation
aws kms enable-key-rotation --key-id $KEY_ID

# Create KMS key policy based on your logging configuration
# Replace placeholders with the actual values from step 1

```bash
# Get your account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

# Create the KMS key policy file (dynamically based on enabled logging)
# Build policy statements array
STATEMENTS='[
  {
    "Sid": "EnableRootUserAccess",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::'${ACCOUNT_ID}':root"
    },
    "Action": "kms:*",
    "Resource": "*"
  }'

# Add CloudWatch statement only if CloudWatch logging is enabled
if [ "$CW_LOG_GROUP" != "None" ] && [ -n "$CW_LOG_GROUP" ]; then
  STATEMENTS+=',
  {
    "Sid": "EnableCloudWatchLogsEncryption",
    "Effect": "Allow",
    "Principal": {
      "Service": [
        "bedrock.amazonaws.com",
        "logs.'${REGION}'.amazonaws.com"
      ]
    },
    "Action": [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ],
    "Resource": "*",
    "Condition": {
      "ArnEquals": {
        "kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:*:'${ACCOUNT_ID}':log-group:'${CW_LOG_GROUP}'"
      }
    }
  }'
fi

# Add S3 statement only if S3 logging is enabled
if [ "$S3_BUCKET" != "None" ] && [ -n "$S3_BUCKET" ]; then
  STATEMENTS+=',
  {
    "Sid": "EnableS3BedrockLogsEncryption", 
    "Effect": "Allow",
    "Principal": {
      "Service": "s3.amazonaws.com"
    },
    "Action": [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "kms:ViaService": "s3.'${REGION}'.amazonaws.com"
      },
      "StringLike": {
        "kms:EncryptionContext:aws:s3:arn": [
          "arn:aws:s3:::'${S3_BUCKET}'/*",
          "arn:aws:s3:::'${S3_BUCKET}'"
        ]
      }
    }
  }'
fi

STATEMENTS+=']'

# Create the policy file
cat > key-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": ${STATEMENTS}
}
EOF
```


# Verify the policy content before applying
echo "Generated KMS key policy:"
cat key-policy.json

# Apply the key policy
```
aws kms put-key-policy \
  --key-id $KEY_ID \
  --policy-name default \
  --policy file://key-policy.json

echo "KMS key policy applied successfully"
```


#### Verify Configuration
```bash

# Verify Bedrock logging configuration
aws bedrock get-model-invocation-logging-configuration
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
# Trigger Config rule evaluation (note: correct rule name)
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-06-model-logs-kms
```

### 2. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-06-model-logs-kms
```

### 3. Expected Results
**S3 Bucket with Customer-Managed KMS:**
- **Status:** COMPLIANT (if bucket is used for Bedrock logging)
- **Reason:** S3 bucket uses customer-managed KMS key for encryption

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the KMS key ID in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-06-model-logs-kms`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the **KmsKeyId** value to the actual key ID (use `echo $KEY_ID` to see the value)
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-06-model-logs-kms \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-06-model-logs-kms
```

### 4. Verify Remediation Results
Check if KMS encryption was configured:

```bash
# Verify S3 bucket encryption configuration
if [ "$S3_BUCKET" != "None" ] && [ -n "$S3_BUCKET" ]; then
  aws s3api get-bucket-encryption --bucket $S3_BUCKET
fi

# Check CloudWatch log group KMS association
if [ "$CW_LOG_GROUP" != "None" ] && [ -n "$CW_LOG_GROUP" ]; then
  aws logs describe-log-groups --log-group-name-prefix $CW_LOG_GROUP
fi
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-06-model-logs-kms

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-06-model-logs-kms

```

### 6. Expected Results (After Automatic Remediation)

**S3 Bucket with Customer-Managed KMS:**
- **Status:** COMPLIANT
- **Reason:** S3 bucket uses customer-managed KMS key for encryption

**CloudWatch Log Group with KMS:**
- **Status:** COMPLIANT  
- **Reason:** CloudWatch log group is encrypted with customer-managed KMS key

## Test Scenarios

### Scenario 1: S3 Bucket with Customer-Managed KMS
S3 bucket configured with customer-managed KMS key.
**Expected Result:** COMPLIANT (if used for Bedrock logging)

### Scenario 2: S3 Bucket with AWS-Managed KMS
S3 bucket using AWS-managed encryption.
**Expected Result:** NON_COMPLIANT

### Scenario 3: S3 Bucket with No Encryption
S3 bucket without encryption.
**Expected Result:** NON_COMPLIANT

### Scenario 4: CloudWatch Log Group with Customer-Managed KMS
CloudWatch log group configured with customer-managed KMS key.
**Expected Result:** COMPLIANT (if used for Bedrock logging)

### Scenario 5: CloudWatch Log Group with AWS-Managed KMS
CloudWatch log group using AWS-managed encryption.
**Expected Result:** NON_COMPLIANT

### Scenario 6: CloudWatch Log Group with No KMS Association
CloudWatch log group without KMS encryption.
**Expected Result:** NON_COMPLIANT

## Cleanup Test Resources
```bash
# Schedule KMS key for deletion (7-day waiting period)
aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Delete key alias
aws kms delete-alias --alias-name alias/bedrock-logs-test

# Clean up policy files
rm -f key-policy.json
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-06-model-logs-kms`


