# FMI-13: Guardrail Word Policy

## Description
Validates that Bedrock guardrails have appropriate word filtering policies configured to block or flag specific words and phrases. This control ensures that guardrails are properly configured with word-based content filtering for AI safety by checking for blocked words and managed word lists.

**Config Resource Type:** `AWS::Bedrock::Guardrail`

## Prerequisites
- Amazon Bedrock guardrails must be created
- Word filtering policies must be defined
- If guardrails use customer-managed KMS encryption (FMI-08), the KMS key policy must allow the Lambda function to access encrypted guardrail details:

```json
{
  "Sid": "AllowLambdaFunction",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-18-guardrail-word-filters-check-role"
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
- **FMI-17:** Guardrail Content Filters - Complementary content filtering
- **FMI-19:** Guardrail Sensitive Information - Related information filtering

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess guardrail word policy compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `BlockedWords` | String | Comma-separated list of specific words to validate | `null` | Optional |
| `ManagedWordLists` | String | Comma-separated list of managed word list types to validate | `PROFANITY` | Optional |
| `InputAction` | String | Input action for word policy (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for word policy (BLOCK or NONE) | `BLOCK` | Optional |
| `RequiredTags` | String | Optional required tags in key=value,key2=value2 format | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `BlockedWords` | String | Comma-separated list of specific words to block | `null` | Optional |
| `ManagedWordLists` | String | Comma-separated list of managed word list types (PROFANITY) | `PROFANITY` | Optional |
| `InputAction` | String | Input action for word policy (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for word policy (BLOCK or NONE) | `BLOCK` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has word policy configured
- Required blocked words are present and enabled (input and/or output)
- Required managed word lists are present and enabled (e.g., PROFANITY)
- Input/output actions match specified requirements (BLOCK or NONE)
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Word policy not configured in guardrail
- Word policy exists but has no words or managed word lists configured
- Missing required blocked words or managed word lists
- Word policy issues (wrong actions, not enabled)
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure word policy configuration is provided
2. **Generate guardrail name** if not specified (format: WordPolicyGuardrail-YYYYMMDDHHMMSS)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure blocked words** and managed word lists (PROFANITY) with BLOCK actions
6. **Enable input and output filtering** for word policy violations
7. **Apply remediation tags** (CreatedBy=AWSConfigRemediation, SafeguardType=WordPolicy)

