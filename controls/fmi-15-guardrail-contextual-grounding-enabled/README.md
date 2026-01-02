# FMI-15: Guardrail Contextual Grounding

## Description
Ensures that Bedrock guardrails have contextual grounding policies configured to prevent hallucinations and ensure factual accuracy. This control validates that guardrails have proper contextual grounding filters with appropriate thresholds and actions to maintain AI response quality and reliability.

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
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-20-guardrail-contextual-grounding-check-role"
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
Parameters used by the evaluation Lambda function to assess guardrail contextual grounding policy compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `FilterTypes` | String | Comma-separated list of contextual grounding filter types to validate | `GROUNDING,RELEVANCE` | Optional |
| `GroundingThreshold` | String | Minimum threshold for grounding filter (0.0-1.0) | `0.75` | Optional |
| `RelevanceThreshold` | String | Minimum threshold for relevance filter (0.0-1.0) | `0.75` | Optional |
| `FilterAction` | String | Action for contextual grounding violations (BLOCK or NONE) | `BLOCK` | Optional |
| `RequiredTags` | String | Optional required tags in key=value,key2=value2 format | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `FilterTypes` | String | Comma-separated list of contextual grounding filter types to configure | `GROUNDING,RELEVANCE` | Required |
| `GroundingThreshold` | String | Minimum threshold for grounding filter (0.0-1.0) | `0.75` | Optional |
| `RelevanceThreshold` | String | Minimum threshold for relevance filter (0.0-1.0) | `0.75` | Optional |
| `FilterAction` | String | Action for contextual grounding violations (BLOCK or NONE) | `BLOCK` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has contextual grounding policy configured
- Required filter types are present and enabled
- Filter thresholds meet minimum requirements
- Filter actions match specified requirements
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Contextual grounding policy not configured in guardrail
- Missing required filter types
- Filter thresholds below minimum requirements
- Filter configuration issues (wrong actions, not enabled)
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure contextual grounding policy configuration is provided
2. **Generate guardrail name** if not specified (format: ContextualGroundingGuardrail-YYYYMMDDHHMMSS)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure grounding filters** and threshold settings for contextual validation
6. **Enable input and output filtering** for contextual grounding violations
7. **Apply remediation tags** (CreatedBy=AWSConfigRemediation, SafeguardType=ContextualGrounding)
