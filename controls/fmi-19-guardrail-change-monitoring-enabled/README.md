# FMI-19: Guardrail Change Monitoring

## Description
Validates that changes to Bedrock guardrails trigger immediate SNS notifications through a simple EventBridge rule. This control ensures that any modifications to AI safety guardrails are detected and reported in real-time.

**Config Resource Type:** `AWS::::Account` (Account-level evaluation)

## Prerequisites
- Amazon Bedrock service available in the region
- SNS topic for notifications (created automatically if not provided)
- CloudTrail enabled to capture API events

## Related Controls
- **FMI-14:** Guardrail CloudWatch Alarms - Complementary monitoring for guardrail usage metrics
- **FMI-13:** CloudTrail Data Events - Provides the underlying API event data that FMI-19 monitors

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailChangeNotificationTopicArn` | String | SNS topic ARN for guardrail change notifications | Auto-created | Optional |
| `EventBridgeRuleName` | String | EventBridge rule name for monitoring | `bedrock-guardrail-change-alerts` | Optional |
| `EventBridgeRuleState` | String | EventBridge rule state (ENABLED/DISABLED) | `ENABLED` | Optional |

### Remediation Function Parameters

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `GuardrailChangeNotificationTopicArn` | String | SNS topic ARN for notifications | Auto-created | Optional |
| `EventBridgeRuleName` | String | EventBridge rule name | `bedrock-guardrail-change-alerts` | Optional |
| `EventBridgeRuleState` | String | EventBridge rule state | `ENABLED` | Optional |
| `KmsKeyId` | String | KMS key ID for SNS topic encryption | `null` | Optional |

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- EventBridge rule exists for Bedrock guardrail API events (CreateGuardrail, UpdateGuardrail, DeleteGuardrail)
- EventBridge rule is in ENABLED state (if expected to be enabled)
- EventBridge rule has SNS topic target configured
- SNS topic exists and is accessible

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No EventBridge rule found for Bedrock guardrail monitoring
- EventBridge rule is disabled
- EventBridge rule missing SNS target
- SNS topic is not accessible or doesn't exist

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for guardrail change monitoring infrastructure.

### Remediation Behavior
When remediation is triggered, the function will:
1. **Create SNS topic** (if not provided) with optional KMS encryption
2. **Create EventBridge rule** for Bedrock guardrail API events using pattern for CreateGuardrail, UpdateGuardrail, DeleteGuardrail
3. **Configure SNS target** for immediate notifications via simple EventBridge → SNS architecture
4. **Set appropriate permissions** for EventBridge to publish to SNS
5. **Validate monitoring setup** functionality

