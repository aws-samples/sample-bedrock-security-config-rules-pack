# FMI-02: Enforce Guardrail for Model Invocation

## Description
Ensures that Service Control Policies (SCPs) mandate the use of guardrails for Bedrock model invocations. Creates individual findings for each relevant SCP to provide detailed compliance status and enforce guardrail usage across the organization.

**Config Resource Type:** `AWS::Organizations::Policy`

## Prerequisites
- AWS Organizations must be enabled
- Service Control Policies must be available
- Appropriate permissions to read organization policies

## Related Controls
- **FMI-01:** Tag-based Access IAM - Complementary access control mechanism
- **FMI-02:** IAM Least Privilege - Works together for comprehensive access control

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredGuardrailArns` | String | Comma-separated list of required guardrail ARNs for SCP enforcement | `arn:aws:bedrock:*:*:guardrail/*` | Optional |
| `AllowedBedrockActions` | String | Comma-separated list of Bedrock actions that must have guardrail conditions | `bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream` | Optional |
| `GuardrailConditionKey` | String | IAM condition key for guardrail enforcement in SCPs | `bedrock:guardrailIdentifier` | Optional |

### Remediation Function Parameters

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredGuardrailArns` | String | Comma-separated list of required guardrail ARNs for SCP enforcement | `arn:aws:bedrock:*:*:guardrail/*` | Optional |
| `AllowedBedrockActions` | String | Comma-separated list of Bedrock actions that must have guardrail conditions | `bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream` | Optional |
| `GuardrailConditionKey` | String | IAM condition key for guardrail enforcement in SCPs | `bedrock:guardrailIdentifier` | Optional |
| `TargetOuId` | String | Organization Unit ID where the SCP should be applied | `root` | Optional |


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- At least one SCP exists with Bedrock restrictions that properly enforces guardrail requirements
- SCP has `Effect: Deny` statements for Bedrock actions (`bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`)
- SCP includes proper conditions:
  - `Null` condition: `bedrock:guardrailIdentifier: true` (requires any guardrail)
  - OR `StringNotEquals` condition with specific required guardrail ARNs
- If `requiredGuardrailArns` parameter is specified, all required ARNs are included in the policy

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No SCPs found that mandate guardrails for Bedrock model invocations
- SCPs with Bedrock restrictions exist but don't properly enforce guardrail requirements
- SCPs missing required guardrail ARNs (if specified in parameters)
- Account is not part of an AWS Organization
- Error occurs while evaluating SCPs

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions at the account level. Individual SCP evaluations may be NOT_APPLICABLE if they don't contain Bedrock-related statements.

### Remediation Behavior
When remediation is triggered, the function will:
1. **Analyze existing SCPs** for guardrail enforcement gaps
2. **Create or update SCP** with required guardrail conditions
3. **Attach policy** to specified organizational units
4. **Validate policy syntax** and effectiveness
5. **Ensure proper condition enforcement** for Bedrock actions
