# FMI-07: Knowledge Bases KMS Encryption - Testing Guide

## Overview
FMI-07 (Knowledge Bases KMS Encryption) ensures customer-managed KMS keys are used for encryption of Bedrock knowledge base data sources. This control validates that knowledge base data sources are properly encrypted at rest using customer-controlled encryption keys.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock knowledge bases with data source configured available in the region
- Permissions to create/manage KMS keys and knowledge bases
- AWS Config enabled and the FMI-07 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-07" --recursive
```



## Test Setup

### 1. Check Current Knowledge Base Configuration
First, identify existing knowledge bases and their data sources:

```bash

# List existing knowledge bases
aws bedrock-agent list-knowledge-bases

# Check data sources in existing knowledge bases (replace KB_ID with actual ID)
aws bedrock-agent list-data-sources --knowledge-base-id KB_ID

# Get account and region info
ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
REGION=$(aws configure get region)

echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
```

**Important:** This control evaluates knowledge base **data sources**, not the knowledge bases themselves. You need knowledge bases with data sources to test this control.

### 2. Create Customer-Managed KMS Key
```bash
# Create a customer-managed KMS key for testing
KEY_ID=$(aws kms create-key --description "Test key for Bedrock knowledge bases" --query 'KeyMetadata.KeyId' --output text)
KEY_ARN=$(aws kms describe-key --key-id $KEY_ID --query 'KeyMetadata.Arn' --output text)
echo "Created KMS Key ID: $KEY_ID"
echo "KMS Key ARN: $KEY_ARN"

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/bedrock-knowledge-bases-test \
  --target-key-id $KEY_ID

# Create KMS key policy for knowledge base access
cat > kb-key-policy.json << EOF
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
      "Sid": "AllowS3VectorsServicePrincipal",
      "Effect": "Allow",
      "Principal": {
        "Service": "indexing.s3vectors.amazonaws.com"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "${ACCOUNT_ID}"
        },
        "ForAnyValue:StringEquals": {
          "kms:EncryptionContextKeys": [
            "aws:s3vectors:arn",
            "aws:s3vectors:resource-id"
          ]
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:s3vectors:${REGION}:${ACCOUNT_ID}:bucket/*"
        }
      }
    }
  ]
}
EOF

# Verify the policy content before applying
echo "Generated KMS key policy:"
cat kb-key-policy.json

# Apply the key policy
aws kms put-key-policy \
  --key-id $KEY_ID \
  --policy-name default \
  --policy file://kb-key-policy.json

echo "KMS key policy applied successfully"
```
### 3. Create Knowle Base if one doesnt exist
## 3.1. Create IAM Role for Knowledge Base
```bash
# Create IAM role for Bedrock Knowledge Base
cat > kb-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "bedrock.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role \
  --role-name AmazonBedrockExecutionRoleForKnowledgeBase \
  --assume-role-policy-document file://kb-trust-policy.json

# Create and attach policy for Knowledge Base operations
cat > kb-permissions-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel"
      ],
      "Resource": "arn:aws:bedrock:*::foundation-model/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "aoss:APIAccessAll"
      ],
      "Resource": "arn:aws:aoss:*:${ACCOUNT_ID}:collection/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "${KEY_ARN}"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name AmazonBedrockExecutionRoleForKnowledgeBase \
  --policy-name BedrockKnowledgeBasePolicy \
  --policy-document file://kb-permissions-policy.json

# Get the role ARN for use in knowledge base creation
KB_ROLE_ARN=$(aws iam get-role --role-name AmazonBedrockExecutionRoleForKnowledgeBase --query 'Role.Arn' --output text)
echo "Knowledge Base Role ARN: $KB_ROLE_ARN"
```

#### 3.2. Create Test Knowledge Bases

**Important:** This control evaluates knowledge base **data sources**, not the knowledge bases themselves. You need to create knowledge bases with data sources to test this control.

#### Using AWS Console (Recommended)
1. **Navigate to Amazon Bedrock Console**
   - Go to AWS Console → Amazon Bedrock → Knowledge bases
   - Click "Create knowledge base"

2. **Create Knowledge Base with Non-Compliant Data Source:**
   - Name: `test-knowledge-base-no-kms`
   - Description: `Test KB with data source without customer KMS encryption`
   - IAM Role: Select the role created in step 3 (`AmazonBedrockExecutionRoleForKnowledgeBase`)
   - Vector database: Choose S3 Vectors (recommended for testing)
   - **Data Source Setup:**
     - Add a data source (S3 bucket)
     - **Important: Do NOT specify a customer-managed KMS key for the data source**
     - Complete the setup with default encryption

3. **Create Knowledge Base with Compliant Data Source:**
   - Name: `test-knowledge-base-with-kms`
   - Description: `Test KB with data source using customer KMS encryption`
   - IAM Role: Same role as above
   - Vector database: Same type as the first KB
   - **Data Source Setup:**
     - Add a data source (S3 bucket)
     - **Important: Specify the KMS key created in step 2 for the data source**
     - Complete the setup

#### Verify Configuration
```bash
# Verify KMS key exists
aws kms describe-key --key-id $KEY_ID

# Verify IAM role exists
aws iam get-role --role-name AmazonBedrockExecutionRoleForKnowledgeBase

# List all knowledge bases to get IDs
aws bedrock-agent list-knowledge-bases

# Set variables for testing (replace with actual IDs)
KB_ID_1="<your-non-compliant-kb-id>"
KB_ID_2="<your-compliant-kb-id>"

# List data sources for each knowledge base
aws bedrock-agent list-data-sources --knowledge-base-id $KB_ID_1
aws bedrock-agent list-data-sources --knowledge-base-id $KB_ID_2
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
# Trigger Config rule evaluation (note: correct rule name)
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-07-knowledge-bases-kms
```

### 2. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-07-knowledge-bases-kms
```

### 3. Expected Results
**Knowledge Base with Data Source using Customer-Managed KMS:**
- **Status:** COMPLIANT
- **Reason:** All knowledge base data sources use customer-managed KMS key for encryption

**Knowledge Base with Data Source without Customer-Managed KMS:**
- **Status:** NON_COMPLIANT
- **Reason:** Knowledge base data sources do not use customer-managed KMS key for encryption

**Knowledge Base with No Data Sources:**
- **Status:** NOT_APPLICABLE
- **Reason:** No data sources found in knowledge base to evaluate for KMS encryption

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the KMS key ID in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-07-knowledge-bases-kms`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the **KmsKeyId** value to the actual key ID (use `echo $KEY_ID` to see the value)
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Trigger remediation for non-compliant knowledge base
aws configservice start-remediation-execution \
  --config-rule-name fmi-07-knowledge-bases-kms \
  --resource-keys resourceType=AWS::Bedrock::KnowledgeBase,resourceId=$KB_ID_1
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-07-knowledge-bases-kms
```

### 4. Verify Remediation Results
Check if data sources were updated with KMS encryption:

```bash
# Check knowledge base data sources for KMS encryption
aws bedrock-agent list-data-sources --knowledge-base-id $KB_ID_1

# Get detailed data source information
DATA_SOURCE_ID=$(aws bedrock-agent list-data-sources --knowledge-base-id $KB_ID_1 --query 'dataSourceSummaries[0].dataSourceId' --output text)
aws bedrock-agent get-data-source --knowledge-base-id $KB_ID_1 --data-source-id $DATA_SOURCE_ID
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-07-knowledge-bases-kms

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-07-knowledge-bases-kms
```

### 6. Expected Results (After Automatic Remediation)

**Knowledge Base Data Sources with Customer-Managed KMS:**
- **Status:** COMPLIANT
- **Reason:** All knowledge base data sources use customer-managed KMS key for encryption

## Test Scenarios

### Scenario 1: Data Source with Customer-Managed KMS
Data source configured with customer-managed KMS key.
**Expected Result:** COMPLIANT

### Scenario 2: Data Source with No KMS Configuration
Data source without serverSideEncryptionConfiguration.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Data Source with Missing KMS Key ARN
Data source has encryption configuration but no kmsKeyArn.
**Expected Result:** NON_COMPLIANT

### Scenario 4: Knowledge Base with No Data Sources
Knowledge base without any data sources configured.
**Expected Result:** NOT_APPLICABLE

### Scenario 5: Unauthorized KMS Key
Use KMS key not in allowed list (if RequiredKmsKeyIds parameter is configured).
**Expected Result:** NON_COMPLIANT

## Cleanup Test Resources
```bash
# Delete knowledge bases (this will also clean up auto-created S3 vector resources)
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_ID_1
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_ID_2

# Delete IAM role and policy
aws iam delete-role-policy \
  --role-name AmazonBedrockExecutionRoleForKnowledgeBase \
  --policy-name BedrockKnowledgeBasePolicy
aws iam delete-role --role-name AmazonBedrockExecutionRoleForKnowledgeBase

# Schedule KMS key for deletion (7-day waiting period)
aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Delete key alias
aws kms delete-alias --alias-name alias/bedrock-knowledge-bases-test

# Clean up policy files
rm -f kb-key-policy.json kb-trust-policy.json kb-permissions-policy.json
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-07-knowledge-bases-kms`
