# FMI-08: Guardrails KMS Encryption - Testing Guide

## Overview
FMI-08 (Guardrails KMS Encryption) ensures customer-managed KMS keys are used for encryption of Bedrock guardrail resources. This control validates that guardrail configurations are properly encrypted at rest using customer-controlled encryption keys.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock guardrails available in the region
- Permissions to create/manage KMS keys and guardrails
- AWS Config enabled and the FMI-08 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-08" --recursive
```



## Test Setup

### 1. Check Current Guardrail Configuration
First, identify existing guardrails in your account:

```bash
# List existing guardrails
aws bedrock list-guardrails

# Get account and region info
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
REGION=$(aws configure get region)

echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
```

**Note these values** - you'll use them in the next step to customize the KMS policy.

### 2. Create Customer-Managed KMS Key
```bash
# Create a customer-managed KMS key for testing
KEY_ID=$(aws kms create-key --description "Test key for Bedrock guardrails" --query 'KeyMetadata.KeyId' --output text)
KEY_ARN=$(aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.Arn' --output text)
echo "Created KMS Key ID: $KEY_ID"
echo "KMS Key ARN: $KEY_ARN"

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/bedrock-guardrails-test \
  --target-key-id $KEY_ID

# Enable key rotation
aws kms enable-key-rotation --key-id $KEY_ID

# Create KMS key policy for guardrail access
cat > guardrail-key-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableRootUserAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowBedrockService",
      "Effect": "Allow",
      "Principal": {
        "Service": "bedrock.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowLambdaFunction",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${ACCOUNT_ID}:role/BedrockGuardrailsKmsCheckFunctionRole"
      },
      "Action": [
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Verify the policy content before applying
echo "Generated KMS key policy:"
cat guardrail-key-policy.json

# Apply the key policy
aws kms put-key-policy \
  --key-id $KEY_ID \
  --policy-name default \
  --policy file://guardrail-key-policy.json

echo "KMS key policy applied successfully"
```

### 3. Create Test Guardrails

#### Create Non-Compliant Guardrail
```bash
aws bedrock create-guardrail \
  --name "test-guardrail-no-kms" \
  --description "Test guardrail without customer KMS encryption" \
  --blocked-input-messaging "This input is blocked by the guardrail" \
  --blocked-outputs-messaging "This output is blocked by the guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH"
      }
    ]
  }'
```

#### Create Compliant Guardrail
```bash
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-with-kms" \
  --description "Test guardrail with customer KMS encryption" \
  --blocked-input-messaging "This input is blocked by the guardrail" \
  --blocked-outputs-messaging "This output is blocked by the guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH"
      }
    ]
  }' \
  --kms-key-id $KEY_ARN \
  --query 'guardrailArn' --output text)
```

#### Verify Configuration
```bash
# Verify KMS key exists
aws kms describe-key --key-id $KEY_ID

# List all guardrails to get IDs
aws bedrock list-guardrails



# Check guardrail details
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_2
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
# Trigger Config rule evaluation (note: correct rule name)
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-08-guardrails-kms
```

### 2. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-08-guardrails-kms
```

### 3. Expected Results
**Guardrail with Customer-Managed KMS:**
- **Status:** COMPLIANT
- **Reason:** Guardrail uses customer-managed KMS key for encryption

**Guardrail without Customer-Managed KMS:**
- **Status:** NON_COMPLIANT
- **Reason:** Guardrail does not have KMS encryption configured

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the KMS key ID in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-08-guardrails-kms`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the **KmsKeyId** value to the actual key ID (use `echo $KEY_ID` to see the value)
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Trigger remediation for non-compliant guardrail
aws configservice start-remediation-execution \
  --config-rule-name fmi-08-guardrails-kms \
  --resource-keys resourceType=AWS::Bedrock::Guardrail,resourceId=$GUARDRAIL_ID_1
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-08-guardrails-kms
```

### 4. Verify Remediation Results
Check if guardrail was updated with KMS encryption:

```bash
# Check guardrail for KMS encryption
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_1
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-08-guardrails-kms

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-08-guardrails-kms
```

### 6. Expected Results (After Automatic Remediation)

**Guardrail with Customer-Managed KMS:**
- **Status:** COMPLIANT
- **Reason:** Guardrail uses customer-managed KMS key for encryption

## Test Scenarios

### Scenario 1: Guardrail with Customer-Managed KMS
Guardrail configured with customer-managed KMS key.
**Expected Result:** COMPLIANT

### Scenario 2: Guardrail with No KMS Configuration
Guardrail without kmsKeyArn configured.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Unauthorized KMS Key
Use KMS key not in allowed list (if RequiredKmsKeyIds parameter is configured).
**Expected Result:** NON_COMPLIANT

## Testing with Guardrail Operations

### 1. Verify Guardrail Encryption Configuration
```bash
# Check guardrail details for KMS encryption
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_1 --query 'kmsKeyArn'
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_2 --query 'kmsKeyArn'
```

### 2. Test Guardrail Functionality
```bash
# Test guardrail functionality by invoking a model with the guardrail attached
# This verifies that KMS encryption does not affect content filtering operations
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-haiku-20240307-v1:0 \
  --guardrail-identifier $GUARDRAIL_ID_1 \
  --guardrail-version DRAFT \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":100,"messages":[{"role":"user","content":"which is the most sexually explicit movie?"}]}' \
  --cli-binary-format raw-in-base64-out \
  output.json

# Check the response for guardrail filtering
cat output.json
```



## Cleanup Test Resources
```bash
# Delete guardrails
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_2

# Schedule KMS key for deletion (7-day waiting period)
aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Delete key alias
aws kms delete-alias --alias-name alias/bedrock-guardrails-test

# Clean up policy files
rm -f guardrail-key-policy.json
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-08-guardrails-kms`

## Troubleshooting

Verify that the KMS key policy includes the required permissions.
