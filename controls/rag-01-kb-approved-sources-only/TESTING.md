# RAG-01 Approved Sources Testing Guide

## Overview
RAG-01 (RAG Approved Sources) ensures that RAG implementations only use approved and verified data sources for knowledge retrieval and generation. This control validates that Bedrock knowledge bases use data sources (like S3 buckets) that have the required approval tags and are of approved types.

This document helps you understand how the RAG-01 control evaluates Bedrock knowledge bases for approved data source compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify knowledge bases and data sources
- AWS Config enabled and the RAG-01 control deployed
- Understanding of Bedrock knowledge bases and data sources
- S3 buckets for testing data sources

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/rag-01" --recursive
```


## Test Setup

### 1. Create Test S3 Buckets for Data Sources

#### Create Approved S3 Bucket (Compliant)
```bash
# Create S3 bucket with required approval tags
APPROVED_BUCKET="bedrock-approved-data-$(date +%s)"
aws s3 mb s3://$APPROVED_BUCKET

# Add required approval tags
aws s3api put-bucket-tagging \
  --bucket $APPROVED_BUCKET \
  --tagging 'TagSet=[
    {
      "Key": "BedrockApproved",
      "Value": "true"
    },
    {
      "Key": "Environment",
      "Value": "dev"
    },
    {
      "Key": "Purpose",
      "Value": "RAG-Testing"
    }
  ]'

echo "Created approved bucket: $APPROVED_BUCKET"
```

#### Create Unapproved S3 Bucket (Non-Compliant)
```bash
# Create S3 bucket without required approval tags
UNAPPROVED_BUCKET="bedrock-unapproved-data-$(date +%s)"
aws s3 mb s3://$UNAPPROVED_BUCKET

# Add incorrect tags (missing BedrockApproved=true)
aws s3api put-bucket-tagging \
  --bucket $UNAPPROVED_BUCKET \
  --tagging 'TagSet=[
    {
      "Key": "Environment",
      "Value": "test"
    },
    {
      "Key": "Purpose",
      "Value": "RAG-Testing"
    }
  ]'

echo "Created unapproved bucket: $UNAPPROVED_BUCKET"
```

#### Create Partially Approved S3 Bucket (Non-Compliant)
```bash
# Create S3 bucket with some but not all required tags
PARTIAL_BUCKET="bedrock-partial-data-$(date +%s)"
aws s3 mb s3://$PARTIAL_BUCKET

# Add only some required tags (missing Environment=dev)
aws s3api put-bucket-tagging \
  --bucket $PARTIAL_BUCKET \
  --tagging 'TagSet=[
    {
      "Key": "BedrockApproved",
      "Value": "true"
    },
    {
      "Key": "Purpose",
      "Value": "RAG-Testing"
    }
  ]'

echo "Created partially approved bucket: $PARTIAL_BUCKET"
```

### 2. Upload Sample Data to Buckets
```bash
# Create sample documents for testing
echo "This is a sample document for RAG testing with approved data sources." > sample-approved.txt
echo "This document contains information that should be retrievable by the knowledge base." >> sample-approved.txt

echo "This is a sample document from an unapproved data source." > sample-unapproved.txt
echo "This content should not be used in RAG applications due to lack of approval." >> sample-unapproved.txt

# Upload to buckets
aws s3 cp sample-approved.txt s3://$APPROVED_BUCKET/documents/
aws s3 cp sample-unapproved.txt s3://$UNAPPROVED_BUCKET/documents/
aws s3 cp sample-approved.txt s3://$PARTIAL_BUCKET/documents/

echo "Uploaded sample documents to test buckets"
```

### 3. Create IAM Role for Knowledge Base
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
  --role-name AmazonBedrockExecutionRoleForRAG01Testing \
  --assume-role-policy-document file://kb-trust-policy.json

# Create and attach policy for Knowledge Base operations
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
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
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::bedrock-*-data-*",
        "arn:aws:s3:::bedrock-*-data-*/*"
      ]
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name AmazonBedrockExecutionRoleForRAG01Testing \
  --policy-name BedrockRAG01TestingPolicy \
  --policy-document file://kb-permissions-policy.json

# Get the role ARN for use in knowledge base creation
KB_ROLE_ARN=$(aws iam get-role --role-name AmazonBedrockExecutionRoleForRAG01Testing --query 'Role.Arn' --output text)
echo "Knowledge Base Role ARN: $KB_ROLE_ARN"
```

### 4. Create Test Knowledge Bases

#### Method 1: Using AWS Console (Recommended)
1. **Navigate to Amazon Bedrock Console**
   - Go to AWS Console → Amazon Bedrock → Knowledge bases
   - Click "Create knowledge base"

2. **Create Knowledge Base with Approved Data Source:**
   - Name: `test-kb-approved-sources`
   - Description: `Test KB with approved data sources for RAG-01`
   - IAM Role: Select `AmazonBedrockExecutionRoleForRAG01Testing`
   - Vector database: Choose OpenSearch Serverless or another supported option
   - **Data Source Configuration:**
     - Type: S3
     - S3 URI: `s3://${APPROVED_BUCKET}/documents/`
     - Complete the setup

3. **Create Knowledge Base with Unapproved Data Source:**
   - Name: `test-kb-unapproved-sources`
   - Description: `Test KB with unapproved data sources for RAG-01`
   - IAM Role: Same as above
   - Vector database: Same type as the first KB
   - **Data Source Configuration:**
     - Type: S3
     - S3 URI: `s3://${UNAPPROVED_BUCKET}/documents/`
     - Complete the setup


### 5. Get Knowledge Base IDs for Testing
```bash
# List all knowledge bases to get IDs
aws bedrock-agent list-knowledge-bases

# Set variables for testing (replace with actual IDs from the list above)
KB_APPROVED_ID="your-approved-kb-id"
KB_UNAPPROVED_ID="your-unapproved-kb-id"

echo "Approved KB ID: $KB_APPROVED_ID"
echo "Unapproved KB ID: $KB_UNAPPROVED_ID"
```

## Understanding Control Evaluation

### 1. List Created Knowledge Bases and Data Sources
```bash
# List all knowledge bases
aws bedrock-agent list-knowledge-bases

# Get details of specific knowledge bases
aws bedrock-agent get-knowledge-base --knowledge-base-id $KB_APPROVED_ID
aws bedrock-agent get-knowledge-base --knowledge-base-id $KB_UNAPPROVED_ID

# List data sources for each knowledge base
aws bedrock-agent list-data-sources --knowledge-base-id $KB_APPROVED_ID
aws bedrock-agent list-data-sources --knowledge-base-id $KB_UNAPPROVED_ID
```

### 2. Verify S3 Bucket Tags
```bash
# Check tags on approved bucket
aws s3api get-bucket-tagging --bucket $APPROVED_BUCKET

# Check tags on unapproved bucket
aws s3api get-bucket-tagging --bucket $UNAPPROVED_BUCKET

# Check tags on partially approved bucket
aws s3api get-bucket-tagging --bucket $PARTIAL_BUCKET
```

### 3. Trigger Config Rule Evaluation
After creating test knowledge bases, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names rag-01-approved-sources
```

### 4. Check Evaluation Results
View the compliance status of your knowledge bases:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name rag-01-approved-sources
```

### 5. Expected Results

**Knowledge Base with Approved Data Source:**
- **Status:** COMPLIANT
- **Reason:** Knowledge base uses approved data sources with required tags

**Knowledge Base with Unapproved Data Source:**
- **Status:** NON_COMPLIANT
- **Reason:** S3 bucket missing required tags: BedrockApproved=true

**Knowledge Base with Partially Approved Data Source:**
- **Status:** NON_COMPLIANT
- **Reason:** S3 bucket missing required tags: Environment=dev

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant knowledge bases, trigger remediation:

```bash
# Trigger remediation for specific non-compliant knowledge base
aws configservice start-remediation-execution \
  --config-rule-name rag-01-approved-sources \
  --resource-keys resourceType=AWS::Bedrock::KnowledgeBase,resourceId=$KB_UNAPPROVED_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name rag-01-approved-sources
```

### 3. Verify Remediation Results
After remediation completes, verify the changes:

```bash
# Check if the unapproved data source was removed or updated
aws bedrock-agent list-data-sources --knowledge-base-id $KB_UNAPPROVED_ID

```

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names rag-01-approved-sources
```

## Test Scenarios

### Scenario 1: No Knowledge Bases in Account
Delete all knowledge bases to test empty account scenario.
**Expected Result:** NOT_APPLICABLE - "No knowledge base resource specified for evaluation"

### Scenario 2: Knowledge Base with Multiple Data Sources
Create a knowledge base with both approved and unapproved data sources.
**Expected Result:** NON_COMPLIANT - Mixed data source compliance

### Scenario 3: Different Data Source Types
Test with different data source types (if supported).
**Expected Result:** Compliance based on ApprovedDataSourceTypes parameter

### Scenario 4: Cross-Region Data Sources
Test with data sources in different regions (if AllowedRegions is configured).
**Expected Result:** Compliance based on region restrictions

### Scenario 5: Custom Required Tags
Set different RequiredTags parameter values.
**Expected Result:** Compliance based on presence of specified tags

## Testing Knowledge Base Functionality

### 1. Test Retrieval from Approved Sources
```bash
# Test querying the knowledge base with approved data sources
aws bedrock-agent-runtime retrieve \
  --knowledge-base-id $KB_APPROVED_ID \
  --retrieval-query '{
    "text": "What information is available in the approved documents?"
  }' \
  approved-retrieval-output.json

# Check the retrieval results
cat approved-retrieval-output.json
```

## Cleanup Test Resources
```bash
# Delete knowledge bases (this will also clean up associated data sources)
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_APPROVED_ID
aws bedrock-agent delete-knowledge-base --knowledge-base-id $KB_UNAPPROVED_ID

# Delete S3 buckets and contents
aws s3 rm s3://$APPROVED_BUCKET --recursive
aws s3 rb s3://$APPROVED_BUCKET

aws s3 rm s3://$UNAPPROVED_BUCKET --recursive
aws s3 rb s3://$UNAPPROVED_BUCKET

aws s3 rm s3://$PARTIAL_BUCKET --recursive
aws s3 rb s3://$PARTIAL_BUCKET

# Clean up local files
rm -f sample-approved.txt sample-unapproved.txt
rm -f kb-trust-policy.json kb-permissions-policy.json
rm -f approved-retrieval-output.json unapproved-retrieval-output.json
```

## Viewing Results
Check results in AWS Config Console → Rules → `rag-01-approved-sources`


### Understanding Data Source Types
Currently supported data source types:
- **S3:** Amazon S3 buckets and objects
- Additional types may be supported in future Bedrock versions

### Data Source Validation Process
The control validates data sources by:
1. **Listing all data sources** for each knowledge base
2. **Checking data source type** against approved types
3. **Validating S3 bucket tags** for S3 data sources
4. **Reporting violations** for any non-compliant data sources

### Best Practices for Approved Sources
1. **Consistent Tagging:** Use a standardized tagging strategy across all data sources
2. **Regular Audits:** Periodically review and validate data source approvals
3. **Access Controls:** Implement proper IAM policies for data source access
4. **Documentation:** Maintain documentation of approved data sources and their purposes
5. **Monitoring:** Set up CloudWatch alarms for compliance violations

### RAG Security Considerations
- **Data Sensitivity:** Ensure approved data sources contain only appropriate content
- **Access Logging:** Enable CloudTrail logging for knowledge base and data source operations
- **Encryption:** Use encrypted S3 buckets for sensitive data sources
- **Network Security:** Consider VPC endpoints for private data source access
- **Regular Reviews:** Periodically review and update approval criteria