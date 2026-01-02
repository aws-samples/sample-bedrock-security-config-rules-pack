# FMI-18: Guardrail CloudWatch Alarms - Testing Guide

## Overview
FMI-18 (Guardrail CloudWatch Alarms) validates that CloudWatch alarms are configured for Bedrock guardrail metrics to monitor guardrail effectiveness and trigger alerts.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Bedrock guardrails created and generating metrics
- CloudWatch service available
- AWS Config enabled and the FMI-18 control deployed


### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-18" --recursive
```

## Test Setup

**Note:** This control automatically creates an SNS topic during remediation if one is not provided. No manual setup is required for basic testing.

### 1. Create Test Guardrail
```bash
# Create guardrail to generate metrics
GUARDRAIL_ID=$(aws bedrock create-guardrail \
  --name "test-guardrail-for-alarms" \
  --description "Test guardrail for CloudWatch alarm testing" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH"
      }
    ]
  }' \
  --query 'guardrailId' --output text)
```

### 2. Generate Guardrail Metrics (Optional)
```bash
# Invoke model with guardrail to generate metrics
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body '{"inputText": "This is inappropriate content that should be blocked"}' \
  --content-type application/json \
  --accept application/json \
  --guardrail-identifier $GUARDRAIL_ID \
  --guardrail-version "1" \
  output.json
```

## Understanding Control Evaluation

### 1. Check Existing CloudWatch Alarms
```bash
# List existing alarms for Bedrock guardrails
aws cloudwatch describe-alarms \
  --alarm-name-prefix "bedrock-guardrail" \
  --query 'MetricAlarms[*].[AlarmName,MetricName,Namespace,Statistic]' \
  --output table
```

### 2. Trigger Config Rule Evaluation (Non-Compliant State)
```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-18-guardrail-cloudwatch-alarms
```

### 3. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-18-guardrail-cloudwatch-alarms
```

### 4. Expected Results (Before Creating Alarms)
**Missing Guardrail Alarms:**
- **Status:** NON_COMPLIANT
- **Reason:** Required CloudWatch alarms for guardrail metrics are missing

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the alarm parameters in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-18-guardrail-cloudwatch-alarms`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, all parameters are optional with defaults, but you may update:
   - **snsTopicArn**: Use the SNS topic ARN from test setup step 1 (use `echo $SNS_TOPIC_ARN` to see the value) for notifications
   - Other parameters can use their default values
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-18-guardrail-cloudwatch-alarms \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-18-guardrail-cloudwatch-alarms
```

### 4. Verify Remediation Results
Check if CloudWatch alarms were created:

```bash
# Check created alarms
aws cloudwatch describe-alarms \
  --alarm-names "bedrock-guardrail-blocked-alarm" "bedrock-guardrail-triggered-alarm" \
  --query 'MetricAlarms[*].[AlarmName,StateValue,AlarmActions]' \
  --output table
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-18-guardrail-cloudwatch-alarms

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-18-guardrail-cloudwatch-alarms
```

### 6. Expected Results (After Automatic Remediation)

**CloudWatch Alarms for Guardrail Metrics:**
- **Status:** COMPLIANT
- **Reason:** Required CloudWatch alarms for guardrail metrics are configured
# Re-trigger evaluation
```
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-18-guardrail-cloudwatch-alarms
```

### 5. Expected Results (After Creating Alarms)
**With Guardrail Alarms:**
- **Status:** COMPLIANT
- **Reason:** Required CloudWatch alarms for guardrail metrics are properly configured

## Test Scenarios

### Scenario 1: Missing Required Alarms
No CloudWatch alarms configured for guardrail metrics.
**Expected Result:** NON_COMPLIANT

### Scenario 2: Alarms Without Actions
Alarms exist but don't have notification actions configured.
**Expected Result:** NON_COMPLIANT (if requireAlarmActions is true)

### Scenario 3: Partial Alarm Coverage
Alarms for some but not all required metrics.
**Expected Result:** NON_COMPLIANT

### Scenario 4: Complete Alarm Coverage
Alarms for all required metrics with proper actions.
**Expected Result:** COMPLIANT

## Testing Alarm Functionality

### 1. Test Alarm Triggering
```bash
# Generate guardrail events to test alarm triggering
for i in {1..3}; do
  aws bedrock-runtime invoke-model \
    --model-id amazon.titan-text-express-v1 \
    --body '{"inputText": "Inappropriate content test '$i'"}' \
    --content-type application/json \
    --accept application/json \
    --guardrail-identifier $GUARDRAIL_ID \
    --guardrail-version "1" \
    output$i.json
  sleep 10
done
```

### 2. Check Alarm State
```bash
# Check if alarms are triggered
aws cloudwatch describe-alarms \
  --alarm-names "bedrock-guardrail-blocked-alarm" \
  --query 'MetricAlarms[*].[AlarmName,StateValue,StateReason]' \
  --output table
```

### 3. View Alarm History
```bash
# Check alarm history
aws cloudwatch describe-alarm-history \
  --alarm-name "bedrock-guardrail-blocked-alarm" \
  --max-records 5
```

## Cleanup Test Resources
```bash
# Delete CloudWatch alarms
aws cloudwatch delete-alarms \
  --alarm-names "bedrock-guardrail-blocked-alarm" "bedrock-guardrail-triggered-alarm"

# Delete test guardrail
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID

# Delete SNS topic
aws sns delete-topic --topic-arn $SNS_TOPIC_ARN

# Clean up output files
rm -f output*.json
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-18-guardrail-cloudwatch-alarms`

## Troubleshooting

### Common Issues
1. **No metrics available:** Ensure guardrails are being used and generating metrics
2. **Alarm creation fails:** Check CloudWatch permissions
3. **SNS topic issues:** Verify SNS topic exists and permissions
4. **Config rule not evaluating:** Verify alarms exist in the account
5. **Lambda function errors:** Check CloudWatch logs:
   ```bash
   aws logs describe-log-groups --log-group-name-prefix /aws/lambda/GuardrailAlarmsCheck
   ```

### Verification Steps
1. Confirm guardrails exist and are generating metrics
2. Verify CloudWatch service is available
3. Check that alarm names match the specified pattern
4. Ensure SNS topics exist for alarm actions
5. Test alarm functionality with actual guardrail events
6. Allow time for Config evaluation to complete
