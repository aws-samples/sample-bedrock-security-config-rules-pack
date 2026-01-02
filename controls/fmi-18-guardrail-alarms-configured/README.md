# FMI-18: Guardrail CloudWatch Alarms

## Description
Validates that CloudWatch alarms are configured for Bedrock guardrail metrics to monitor guardrail effectiveness and trigger alerts when thresholds are exceeded. This control ensures proper monitoring of AI safety mechanisms.

**Config Resource Type:** `AWS::CloudWatch::Alarm`

## Prerequisites
- Amazon Bedrock guardrails must be created
- CloudWatch alarms must be configured for guardrail metrics



## Related Controls
- **FMI-15:** Guardrail Change Monitoring - Complementary monitoring for configuration changes
- **FMI-08:** Guardrails KMS - Encryption requirements for guardrails

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `AlarmThreshold` | Number | Threshold value for guardrail alarms | `1` | Optional |

### Remediation Function Parameters

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.
| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `AlarmThreshold` | Number | Threshold value for CloudWatch alarms | `1` | Optional |
| `MetricNamespace` | String | CloudWatch metric namespace for guardrail metrics | `Bedrock/Guardrails` | Optional |
| `AlarmNamePrefix` | String | Prefix for CloudWatch alarm names | `BedrockGuardrail` | Optional |
| `GuardrailChangeNotificationTopicArn` | String | SNS topic ARN for alarm notifications (leave empty to create new topic) | `null` | Optional |
| `KmsKeyId` | String | KMS key ID for SNS topic encryption (leave empty to disable encryption) | `null` | Optional |



## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- CloudWatch metric filters exist for guardrail interventions using pattern `{($.output.outputBodyJson.stopReason = "guardrail_intervened")}`
- CloudWatch alarms are configured for the metric filters with correct threshold (default: 1)
- Alarms have actions configured for notifications
- Model invocation logging is enabled for Bedrock

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No metric filters found for guardrail intervention monitoring
- Metric filters exist but no properly configured alarms
- Alarms exist but no metric filters for guardrail interventions
- Model invocation logging is not configured
- Alarms have incorrect threshold or missing actions

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- No guardrails exist in the account to monitor

### Remediation Behavior
When remediation is triggered, the function will:
1. **Create metric filters** for guardrail intervention monitoring using the pattern `{($.output.outputBodyJson.stopReason = "guardrail_intervened")}`
2. **Create CloudWatch alarms** for the metric filters with specified threshold
3. **Configure alarm actions** using the provided SNS topic ARN
4. **Set up proper metric transformations** in the Bedrock log group
5. **Validate alarm and metric filter configuration**
