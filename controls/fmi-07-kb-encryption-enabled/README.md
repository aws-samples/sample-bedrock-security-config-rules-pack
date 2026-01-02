# FMI-07: Knowledge Bases KMS Encryption

## Description
Ensures customer-managed KMS keys are used for encryption of Bedrock knowledge base data sources. This control validates that knowledge base data sources are properly encrypted at rest using customer-controlled encryption keys.

**Config Resource Type:** `AWS::Bedrock::KnowledgeBase`

## Prerequisites
- Amazon Bedrock knowledge bases with data sources must be created
- Customer-managed KMS keys must be available
- KMS key should have policy statements allowing Bedrock services to use the key:

```json
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
      "aws:SourceAccount": "${AWS::AccountId}"
    },
    "ForAnyValue:StringEquals": {
      "kms:EncryptionContextKeys": [
        "aws:s3vectors:arn",
        "aws:s3vectors:resource-id"
      ]
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:s3vectors:${AWS::Region}:${AWS::AccountId}:bucket/*"
    }
  }
}
```

These statements should be added to your existing KMS key policy alongside the standard root user access statement.
- Appropriate IAM permissions for KMS key usage

## Related Controls
- **FMI-06:** Model Logs KMS - Similar encryption requirements for model logs
- **FMI-08:** Guardrails KMS - Similar encryption requirements for guardrails
- **RAG-02:** Vector DB Encrypted - Complementary vector database encryption control

## Usage Patterns
- RAG (Retrieval-Augmented Generation) - Primary use case
- Agentic AI workflows (when using knowledge bases)

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredKmsKeyIds` | String | Comma-separated list of allowed KMS key IDs/ARNs for encryption | `null` - (accepts any customer-managed key) | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `KmsKeyId` | String | KMS key ID to use for encryption | `null` | Required |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must:
- **Provide a valid KMS key ID** that exists in your account
- **Ensure the KMS key policy** allows Bedrock service access (see Prerequisites section)
- **Update the SSM parameter** `/bedrock-configrules/fmi-07/KmsKeyId` with your key ID before running remediation




## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Knowledge base has data sources configured
- All data sources have `serverSideEncryptionConfiguration` with `kmsKeyArn`
- If `RequiredKmsKeyIds` parameter is specified, KMS key ID matches the approved list
- All data sources use customer-managed KMS keys for encryption

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- Data source lacks `serverSideEncryptionConfiguration`
- Data source has no `kmsKeyArn` specified in encryption configuration
- KMS key ID is not in the `RequiredKmsKeyIds` list (if specified)
- Error occurs while checking data source encryption configuration

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Knowledge base has no data sources configured
- Knowledge base resource not found (may have been deleted)

## Remediation Behavior
When remediation is triggered, the function will:
1. **Identify knowledge base data sources** that lack KMS encryption configuration
2. **Update data sources** to use the specified customer-managed KMS key
3. **Preserve existing encryption** for data sources already using customer-managed keys (even if different)
4. **Generate warnings** for data sources using non-matching KMS keys
5. **Report detailed results** including remediated, compliant, warning, and failed data sources

**Note:** The remediation preserves existing customer-managed KMS encryption to avoid potential data access disruption, even if using different keys than specified.
