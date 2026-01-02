# FMI-12: Guardrail Content Filters

## Description
Validates that Bedrock guardrails have comprehensive content filtering policies configured to block harmful, inappropriate, or unsafe content. This control ensures proper AI safety and content moderation capabilities by verifying that guardrails have appropriate content filters with sufficient strength levels and proper actions.

**Config Resource Type:** `AWS::Bedrock::Guardrail`

## Prerequisites
- Amazon Bedrock guardrails must be created
- Appropriate monitoring and filtering infrastructure
- If guardrails use customer-managed KMS encryption (FMI-08), the KMS key policy must allow the Lambda function to access encrypted guardrail details:

```json
{
  "Sid": "AllowLambdaFunction",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-17-guardrail-content-filters-check-role"
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
- **FMI-08:** Guardrails KMS - Encryption requirements for guardrails
- **FMI-14:** Guardrail CloudWatch Alarms - Monitoring and alerting

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess guardrail content filter compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `ContentFilters` | String | Comma-separated list of content filter types to validate | `SEXUAL,VIOLENCE,HATE,INSULTS` | Optional |
| `InputStrength` | String | Minimum input strength for content filters (NONE, LOW, MEDIUM, HIGH) | `MEDIUM` | Optional |
| `OutputStrength` | String | Minimum output strength for content filters (NONE, LOW, MEDIUM, HIGH) | `MEDIUM` | Optional |
| `InputAction` | String | Input action for content filters (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for content filters (BLOCK or NONE) | `BLOCK` | Optional |
| `RequiredTags` | String | Optional required tags in key=value,key2=value2 format | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `ContentFilters` | String | Comma-separated list of content filter types to configure | `SEXUAL,VIOLENCE,HATE,INSULTS` | Required |
| `InputStrength` | String | Input strength for content filters (NONE, LOW, MEDIUM, HIGH) | `MEDIUM` | Optional |
| `OutputStrength` | String | Output strength for content filters (NONE, LOW, MEDIUM, HIGH) | `MEDIUM` | Optional |
| `InputAction` | String | Input action for content filters (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for content filters (BLOCK or NONE) | `BLOCK` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has content policy configured
- Required content filters are present and enabled (input and/or output)
- Filter strength meets minimum requirements (NONE < LOW < MEDIUM < HIGH)
- Input/output actions match specified requirements (BLOCK or NONE)
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Content policy not configured in guardrail
- No content filters configured in content policy
- Missing required content filters
- Content filter issues (insufficient strength, wrong actions, not enabled)
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure ContentFilters is provided
2. **Generate guardrail name** if not specified (format: ContentFilterGuardrail-YYYYMMDDHHMMSS)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure content policy** with required content filters (SEXUAL, VIOLENCE, HATE, INSULTS)
6. **Set filter strength** to meet minimum requirements (MEDIUM or higher)
7. **Enable input/output filtering** with specified actions (BLOCK/NONE)
8. **Apply standard tags** for tracking and identification purposes
