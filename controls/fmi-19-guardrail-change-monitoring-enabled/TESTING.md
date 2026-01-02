# FMI-19: Guardrail Change Monitoring - Testing Guide

## Overview
FMI-19 (Guardrail Change Monitoring) validates that simple EventBridge → SNS monitoring exists to detect and immediately alert on Bedrock guardrail configuration changes. This control ensures that any modifications to AI safety guardrails trigger immediate SNS notifications.

This document helps you understand how to test the simplified FMI-19 control.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Bedrock service available in the region
- AWS Config enabled and the FMI-19 control deployed
- Email address for receiving test notifications

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-19" --recursive
```

## Test Setup

**Note:** This control automatically creates an SNS topic during remediation if one is not provided. No manual setup is required for basic testing.



## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-19-guardrail-change-monitoring
```

### 2. Check Evaluation Results
```bash
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-19-guardrail-change-monitoring
```

### 3. Expected Results
**No EventBridge Rule:** NON_COMPLIANT
**EventBridge Rule → SNS Configured:** COMPLIANT

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, you can update the parameters in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-19-guardrail-change-monitoring`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, all parameters are optional with defaults, but you may update:
   - **GuardrailChangeNotificationTopicArn**: Use your own SNS topic ARN for notifications
   - Other parameters can use their default values
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-19-guardrail-change-monitoring \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Check Remediation Status
```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-19-guardrail-change-monitoring
```

### 4. Verify Remediation Results
Check if EventBridge rule and SNS topic were created:

```bash
# Check EventBridge rule
aws events describe-rule --name bedrock-guardrail-change-alerts

# Check SNS topics
aws sns list-topics --query 'Topics[?contains(TopicArn, `guardrail`)]'

# Check EventBridge rule targets
aws events list-targets-by-rule --rule bedrock-guardrail-change-alerts
```

### 5. Re-evaluate After Remediation
```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-19-guardrail-change-monitoring

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-19-guardrail-change-monitoring
```

### 6. Expected Results (After Remediation)
- **Status:** COMPLIANT
- **Reason:** EventBridge rule exists with SNS target for guardrail change alerts

## Testing Alert Functionality

### 1. Create Test Guardrail to Trigger Alert
```bash
# Create a guardrail to test the alert system
GUARDRAIL_ID=$(aws bedrock create-guardrail \
  --name "test-alert-guardrail-$(date +%s)" \
  --description "Test guardrail for alert testing" \
  --blocked-input-messaging "Input blocked" \
  --blocked-outputs-messaging "Output blocked" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "MEDIUM",
        "outputStrength": "MEDIUM"
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created test guardrail: $GUARDRAIL_ID"
echo "Check your email for SNS notification!"
```

### 2. Update Test Guardrail to Trigger Another Alert
```bash
# Update the guardrail to trigger another alert
aws bedrock update-guardrail \
  --guardrail-identifier $GUARDRAIL_ID \
  --name "updated-test-alert-guardrail" \
  --description "Updated test guardrail for alert testing" \
  --blocked-input-messaging "Input blocked - updated" \
  --blocked-outputs-messaging "Output blocked - updated" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH"
      }
    ]
  }'

echo "Updated test guardrail: $GUARDRAIL_ID"
echo "Check your email for another SNS notification!"
```

### 3. Delete Test Guardrail to Trigger Final Alert
```bash
# Delete the guardrail to trigger a delete alert
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID

echo "Deleted test guardrail: $GUARDRAIL_ID"
echo "Check your email for the final SNS notification!"
```

## Test Scenarios

### Scenario 1: No EventBridge Rule
- **Setup:** Fresh account with no monitoring
- **Expected Result:** NON_COMPLIANT
- **Remediation:** Creates EventBridge rule and SNS topic

### Scenario 2: EventBridge Rule Exists but Disabled
- **Setup:** Rule exists but State = DISABLED
- **Expected Result:** NON_COMPLIANT (if expected state is ENABLED)
- **Remediation:** Enables the rule

### Scenario 3: Complete Monitoring Setup
- **Setup:** EventBridge rule with SNS target
- **Expected Result:** COMPLIANT

### 4. Verify Alert Content and Configuration

When you receive SNS notifications, they should contain:
- **Event Source:** aws.bedrock
- **Event Name:** CreateGuardrail, UpdateGuardrail, or DeleteGuardrail
- **Guardrail ID:** The affected guardrail identifier
- **Account ID:** Your AWS account ID
- **Region:** The AWS region where the change occurred
- **Timestamp:** When the change occurred

You can also verify the monitoring configuration:
```bash
# Check EventBridge rule details
aws events describe-rule --name bedrock-guardrail-change-alerts

# Check rule targets
aws events list-targets-by-rule --rule bedrock-guardrail-change-alerts

# Get SNS topic attributes (if you have the topic ARN)
aws sns get-topic-attributes --topic-arn $SNS_TOPIC_ARN
```

## Cleanup Test Resources
```bash
# Delete test guardrail (if still exists)
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID

# Delete test SNS topic (if created)
aws sns delete-topic --topic-arn $SNS_TOPIC_ARN

# Optionally delete EventBridge rule (will be recreated by remediation)
aws events remove-targets --rule bedrock-guardrail-change-alerts --ids guardrail-sns-target
aws events delete-rule --name bedrock-guardrail-change-alerts
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-19-guardrail-change-monitoring`

## Troubleshooting

### Common Issues
1. **No SNS notifications received:**
   - Check email subscription confirmation
   - Verify EventBridge rule has SNS target
   - Check SNS topic permissions

2. **EventBridge rule not triggering:**
   - Verify CloudTrail is enabled
   - Check rule event pattern
   - Ensure rule is in ENABLED state

3. **Config rule evaluation fails:**
   - Check Lambda function logs in CloudWatch
   - Verify IAM permissions
   - Check rule parameters

### Debugging Commands
```bash
# Check CloudWatch logs for Lambda function
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/BedrockGuardrail"

# Get recent log events
aws logs filter-log-events \
  --log-group-name "/aws/lambda/BedrockGuardrailChangeMonitoringCheck" \
  --start-time $(date -d '1 hour ago' +%s)000

# Check CloudTrail events for guardrail changes
aws logs filter-log-events \
  --log-group-name "CloudTrail/BedrockEvents" \
  --filter-pattern "{ $.eventSource = \"bedrock.amazonaws.com\" && ($.eventName = \"CreateGuardrail\" || $.eventName = \"UpdateGuardrail\" || $.eventName = \"DeleteGuardrail\") }"
```

### Verification Steps
1. Confirm EventBridge rule exists and is enabled
2. Verify SNS topic is accessible and has subscriptions
3. Check CloudTrail is capturing Bedrock API events
4. Test EventBridge rule pattern with sample events

