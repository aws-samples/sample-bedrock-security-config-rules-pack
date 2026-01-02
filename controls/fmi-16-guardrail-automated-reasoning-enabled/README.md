# FMI-16: Guardrail Automated Reasoning

## Description
Validates that Bedrock guardrails have automated reasoning capabilities enabled to improve decision-making and reduce bias. This control ensures proper security and compliance for AI operations by verifying that guardrails have automated reasoning policies with required policy configurations and confidence thresholds.

**Config Resource Type:** `AWS::Bedrock::Guardrail`

> **⚠️ Important Note:** The automated reasoning policy created by the remediation function is a basic sample policy for demonstration purposes only. Organizations must create and configure their own production-ready automated reasoning policies that align with their specific business requirements, compliance needs, and AI governance standards before deploying this control in production environments.

## Prerequisites
- Amazon Bedrock services must be available
- Appropriate configuration and monitoring infrastructure
- **Note:** Automated reasoning is an advanced Bedrock feature that may require specific model support
- If guardrails use customer-managed KMS encryption (FMI-08), the KMS key policy must allow the Lambda function to access encrypted guardrail details:

```json
{
  "Sid": "AllowLambdaFunction",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<Account_Id>:role/fmi-21-guardrail-automated-reasoning-check-role"
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
- **FMI-02:** Enforce Guardrail for Model Invocation

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess guardrail automated reasoning policy compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailName` | String | Optional specific guardrail name to validate | `null` | Optional |
| `AutomatedReasoningPolicies` | String | Comma-separated list of automated reasoning policy ARNs or IDs to validate | `null` | Optional |
| `MinConfidenceThreshold` | String | Minimum confidence threshold for automated reasoning (0.0-1.0) | `0.8` | Optional |
| `RequiredTags` | String | Optional required tags in key=value,key2=value2 format | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `AutomatedReasoningPolicies` | String | Comma-separated list of automated reasoning policy ARNs or IDs. If empty, creates default policy | `null` | Optional |
| `MinConfidenceThreshold` | String | Minimum confidence threshold for automated reasoning (0.0-1.0) | `0.8` | Optional |
| `GuardrailName` | String | Optional specific guardrail name to create or update during remediation | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Guardrail has automated reasoning policy configured
- Required policies are present and configured
- Confidence threshold meets minimum requirements
- Guardrail matches required tags (if specified)
- Guardrail status is "READY"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No guardrails configured in account
- No guardrails match specified criteria (name, tags)
- Automated reasoning policy not configured in guardrail
- Missing required policies
- Confidence threshold below minimum requirements
- Policy configuration issues
- Guardrail not in "READY" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Guardrail resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::Guardrail`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and parse automated reasoning policy configuration
2. **Create automated reasoning policies** if none provided (generates basic consistency check policy)
3. **Check for existing guardrail** with the specified name
4. **Update existing guardrail** if found, or **create new guardrail** if not found
5. **Configure policy limits** (maximum 2 policies per guardrail as per AWS API limits)
6. **Configure reasoning filters** and validation settings with specified confidence threshold
7. **Enable input and output filtering** for automated reasoning violations
8. **Apply remediation tags** (CreatedBy=AWSConfigRemediation, SafeguardType=AutomatedReasoning)
