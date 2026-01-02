# FMI-14: Guardrail Sensitive Information

## Description
Validates that Bedrock guardrails are configured to detect and block sensitive information like PII, financial data, and other confidential content. This control ensures proper security and compliance for AI operations by verifying that guardrails have sensitive information policies with appropriate PII entities and custom regex patterns.

**Config Resource Type:** `AWS::Bedrock::Guardrail`

## Prerequisites
- Amazon Bedrock services must be available
- Appropriate configuration and monitoring infrastructure
- If guardrails use customer-managed KMS encryption (FMI-08), the KMS key policy must allow the Lambda function to access encrypted guardrail details:

```json
{
  "Sid": "AllowLambdaFunction",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-19-guardrail-sensitive-info-check-role"
  },
  "Action": [
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

The Lambda function statement is required to allow the Config rule evaluation function to access encrypted guardrail details for compliance checking.

**Note:** Replace `<Account_Id>` with your actual AWS account ID.

## Related Controls
- **FMI-08:** Guardrails KMS - Encryption requirements
- **FMI-12:** Guardrail IAM Condition - Policy enforcement

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess guardrail sensitive information policy compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `PIIEntities` | String | Comma-separated list of PII entity types to validate | `EMAIL,PHONE,CREDIT_DEBIT_CARD_NUMBER,US_SOCIAL_SECURITY_NUMBER` | Optional |
| `PIIAction` | String | Action for PII entity violations (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `InputAction` | String | Input action for sensitive information policy (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for sensitive information policy (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `RegexPattern1` | String | First custom regex pattern (SSN format example) | `\\d{3}-\\d{2}-\\d{4}` | Optional |
| `RegexPattern2` | String | Second custom regex pattern | `null` | Optional |
| `RegexPattern3` | String | Third custom regex pattern | `null` | Optional |
| `RegexPatternN` | String | n-th custom regex pattern | `null` | Optional |
| `RequiredTags` | String | Optional required tags in key=value,key2=value2 format | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `PIIEntities` | String | Comma-separated list of PII entity types to configure | `EMAIL,PHONE,CREDIT_DEBIT_CARD_NUMBER,US_SOCIAL_SECURITY_NUMBER` | Required |
| `PIIAction` | String | Action for PII entity violations (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `InputAction` | String | Input action for sensitive information policy (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for sensitive information policy (BLOCK, ANONYMIZE, or NONE) | `BLOCK` | Optional |
| `RegexPattern1` | String | First custom regex pattern | `\\d{3}-\\d{2}-\\d{4}` | Optional |
| `RegexPattern2` | String | Second custom regex pattern | `null` | Optional |
| `RegexPattern3` | String | Third custom regex pattern | `null` | Optional |
| `RegexPatternN` | String | n-th custom regex pattern | `null` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has sensitive information policy configured
- Required PII entities are present and enabled
- Custom regex patterns are configured (if specified)
- Input/output actions match specified requirements
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Sensitive information policy not configured in guardrail
- Missing required PII entities or regex patterns
- PII entity or regex pattern configuration issues
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure sensitive information policy configuration is provided
2. **Generate guardrail name** if not specified (format: SensitiveInfoGuardrail-YYYYMMDDHHMMSS)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure PII entities** and custom regex patterns with specified actions
6. **Enable input and output filtering** for sensitive information violations
7. **Apply remediation tags** (CreatedBy=AWSConfigRemediation, SafeguardType=SensitiveInformation)
