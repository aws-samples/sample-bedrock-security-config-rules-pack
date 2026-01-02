# FMI-11: Guardrail Topic Filters

## Description
Ensures that Bedrock guardrails have topic-based filtering configured to prevent discussions of inappropriate or sensitive topics. This control validates that guardrails have proper topic policies configured with DENY actions for specified topics to maintain AI safety and content moderation capabilities.

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
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-16-guardrail-topic-filters-check-role"
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
Parameters used by the evaluation Lambda function to assess guardrail topic filter compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `TopicFilters` | String | Comma-separated list of topic filters to validate | `Violence,HateSpeech,SelfHarm` | Optional |
| `TopicFilterAction` | String | Topic filter action type | `DENY` | Optional |
| `InputAction` | String | Input action for topic filters (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for topic filters (BLOCK or NONE) | `BLOCK` | Optional |
| `Example` | String | Optional example text to validate in topic examples | `null` | Optional |
| `RequiredTags` | String | Filter guardrails by tags - only evaluate guardrails that have all specified tags (format: key=value,key2=value2) | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `TopicFilters` | String | Comma-separated list of topic filters to configure | `Violence,HateSpeech,SelfHarm` | Required |
| `InputAction` | String | Input action for topic filters (BLOCK or NONE) | `BLOCK` | Optional |
| `OutputAction` | String | Output action for topic filters (BLOCK or NONE) | `BLOCK` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has topic policy configured
- Required topic filters are present with type "DENY"
- Topics are enabled for input and/or output filtering
- Input/output actions match specified requirements (BLOCK or NONE)
- Example text is found in topic examples (if specified)
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Topic policy not configured in guardrail
- No topics configured in topic policy
- Missing required topic filters
- Topic action mismatches (wrong input/output actions)
- Example text not found in topic examples
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure TopicFilters is provided
2. **Generate guardrail name** if not specified (format: TopicFilterGuardrail-YYYYMMDDHHMMSS)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure topic filters** for each specified topic with DENY action type
6. **Enable input and output filtering** with specified block actions
7. **Apply standard tags** for tracking and identification purposes
