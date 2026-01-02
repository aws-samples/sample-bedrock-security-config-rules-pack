# RAG-02 Vector Database Encryption Testing Guide

## Overview
RAG-02 (Vector Database Encryption) validates that vector databases used in RAG implementations are properly encrypted at rest and in transit. This control ensures that Bedrock Knowledge Base vector databases use customer-managed KMS keys for encryption to maintain security and compliance for AI operations.

This document helps you understand how the RAG-02 control evaluates Bedrock Knowledge Bases for vector database encryption compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify knowledge bases and vector databases
- AWS Config enabled and the RAG-02 control deployed
- Understanding of Bedrock knowledge bases and vector storage options

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/rag-02" --recursive
```

## Test Setup

### 1. Create Customer-Managed KMS Key for Testing (Optional)
```bash
# Create a customer-managed KMS key for vector database encryption
KEY_ID=$(aws kms create-key \
  --description "Test key for RAG-02 vector database encryption" \
  --query 'KeyMetadata.KeyId' --output text)

echo "Created KMS Key ID: $KEY_ID"

# Create an alias for easier reference
aws kms create-alias \
  --alias-name alias/bedrock-vector-test \
  --target-key-id $KEY_ID
```

### 2. Create Test Knowledge Bases (Using AWS Console)
**Note:** Knowledge base creation with specific encryption settings is best done through the AWS Console.

1. **Navigate to Amazon Bedrock Console** → Knowledge bases → Create knowledge base

2. **Create Knowledge Base with AWS-Managed Encryption (Non-Compliant):**
   - Name: `test-kb-aws-managed-encryption`
   - Vector database: OpenSearch Serverless
   - Encryption: Use AWS-managed encryption (default)

3. **Create Knowledge Base with Customer-Managed Encryption (Compliant):**
   - Name: `test-kb-customer-managed-encryption`
   - Vector database: OpenSearch Serverless
   - Encryption: Use customer-managed KMS key (select the key created above)

### 3. Get Knowledge Base IDs
```bash
# List all knowledge bases to get IDs for testing
aws bedrock-agent list-knowledge-bases --query 'knowledgeBaseSummaries[*].[name,knowledgeBaseId]' --output table

# Set variables for testing (replace with actual IDs)
KB_AWS_MANAGED_ID="your-aws-managed-kb-id"
KB_CUSTOMER_MANAGED_ID="your-customer-managed-kb-id"
```

## Understanding Control Evaluation

### 1. List Created Knowledge Bases
```bash
# List all knowledge bases to verify creation
aws bedrock-agent list-knowledge-bases --query 'knowledgeBaseSummaries[*].[name,knowledgeBaseId,status]' --output table

# Get details of specific knowledge bases
aws bedrock-agent get-knowledge-base --knowledge-base-id $KB_AWS_MANAGED_ID
aws bedrock-agent get-knowledge-base --knowledge-base-id $KB_CUSTOMER_MANAGED_ID
```

### 2. Trigger Config Rule Evaluation
After creating test knowledge bases, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names rag-02-vector-db-encrypted
```

### 3. Check Evaluation Results
View the compliance status of your knowledge bases:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name rag-02-vector-db-encrypted
```

### 4. Expected Results

**Non-Compliant Knowledge Bases:**
- **Status:** NON_COMPLIANT
- **Reason:** Vector database uses AWS managed key (e.g., alias/aws/aoss) when AllowAWSManagedKeys=false, missing encryption configuration, or KMS key doesn't match RequiredKmsKeyId parameter

**Compliant Knowledge Bases:**
- **Status:** COMPLIANT
- **Reason:** Vector database uses customer-managed KMS key for OpenSearch Serverless/RDS/S3 Vectors encryption, or AWS managed key when AllowAWSManagedKeys=true, and matches RequiredKmsKeyId if specified

## Manual Remediation

**Note:** This control does not include automatic remediation functionality. Vector database encryption is immutable and requires manual recreation.

### Manual Remediation Steps
1. **Identify non-compliant knowledge bases** from Config rule evaluation results
2. **Create new customer-managed KMS key** (if needed) with appropriate permissions
3. **Recreate knowledge base** with proper encryption configuration
4. **Update data sources** to point to the new encrypted knowledge base
5. **Delete old non-compliant knowledge base** after verification

### Re-evaluate After Manual Changes
```bash
# Re-trigger evaluation after manual remediation
aws configservice start-config-rules-evaluation \
  --config-rule-names rag-02-vector-db-encrypted

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name rag-02-vector-db-encrypted
```

## Test Scenarios

### Scenario 1: No Knowledge Bases in Account
Delete all knowledge bases to test empty account scenario.
**Expected Result:** No resources to evaluate

### Scenario 2: AWS-Managed Encryption (AllowAWSManagedKeys=false)
Create knowledge base with AWS-managed encryption.
**Expected Result:** NON_COMPLIANT - Customer-managed key required

### Scenario 3: AWS-Managed Encryption (AllowAWSManagedKeys=true)
Set AllowAWSManagedKeys parameter to true and test AWS-managed encryption.
**Expected Result:** COMPLIANT - AWS-managed key allowed

### Scenario 4: Customer-Managed Encryption
Create knowledge base with customer-managed KMS key.
**Expected Result:** COMPLIANT - Uses customer-managed key

### Scenario 5: Specific Required KMS Key
Set RequiredKmsKeyId parameter to test specific key requirement.
**Expected Result:** Compliance based on whether the specific key is used

## Testing Vector Database Functionality

### 1. Test Encrypted Knowledge Base Operations
```bash
# Test retrieval from encrypted knowledge base
aws bedrock-agent-runtime retrieve \
  --knowledge-base-id $KB_CUSTOMER_MANAGED_ID \
  --retrieval-query '{"text": "Test query to encrypted vector database"}'
```

## Cleanup Test Resources
```bash
# Delete knowledge bases (this will also clean up associated vector databases)
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_AWS_MANAGED_ID
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_CUSTOMER_MANAGED_ID

# Schedule KMS key for deletion (7-day waiting period)
aws kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# Delete key alias
aws kms delete-alias --alias-name alias/bedrock-vector-test

# Note: If remediation updated an existing knowledge base, you may need to manually revert changes
# or delete the knowledge base if it was created by remediation

# No output files to clean up
```

## Viewing Results
Check results in AWS Config Console → Rules → `rag-02-vector-db-encrypted`