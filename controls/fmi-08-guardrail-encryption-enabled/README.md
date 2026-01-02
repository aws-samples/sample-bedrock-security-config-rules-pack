# FMI-08: Guardrails KMS Encryption

## Description
Ensures customer-managed KMS keys are used for encryption of Bedrock guardrail resources. This control validates that guardrail configurations and data are properly encrypted at rest using customer-controlled encryption keys.

**Config Resource Type:** `AWS::Bedrock::Guardrail`

## Prerequisites
- Amazon Bedrock guardrails must be created
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
  "Sid": "AllowLambdaFunction",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<Account_Id>:role/BedrockGuardrailsKmsCheckFunctionRole"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

The Lambda function statement is required to allow the Config rule evaluation function to access encrypted guardrail details for compliance checking.

These statements should be added to your existing KMS key policy alongside the standard root user access statement.
- Appropriate IAM permissions for KMS key usage

## Related Controls
- **FMI-06:** Model Logs KMS - Similar encryption requirements for model logs
- **FMI-07:** Knowledge Bases KMS - Similar encryption requirements for knowledge bases

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

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
- **Update the SSM parameter** `/bedrock-configrules/fmi-08/KmsKeyId` with your key ID before running remediation


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has `kmsKeyArn` configured in its details
- If `RequiredKmsKeyIds` parameter is specified, KMS key ID matches the approved list
- Guardrail uses customer-managed KMS key for encryption

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- Guardrail does not have `kmsKeyArn` configured (no KMS encryption)
- KMS key ID is not in the `RequiredKmsKeyIds` list (if specified)
- Error occurs while checking guardrail KMS encryption configuration

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Check guardrail configuration** for existing KMS encryption
2. **Add customer-managed KMS encryption** to guardrails lacking encryption
3. **Preserve existing encryption** for guardrails already using customer-managed keys (even if different)
4. **Generate warnings** for guardrails using non-matching KMS keys
5. **Update guardrail configuration** with the specified KMS key

**Note:** The remediation preserves existing customer-managed KMS encryption to avoid potential access disruption, even if using different keys than specified.
