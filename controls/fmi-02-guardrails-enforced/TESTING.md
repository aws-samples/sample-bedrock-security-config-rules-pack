# FMI-02: Enforce Guardrail for Model Invocation - Testing Guide

## Overview
FMI-02 (Enforce Guardrail for Model Invocation) ensures that Service Control Policies mandate the use of guardrails for Bedrock model invocations across the organization.

## Prerequisites
- AWS Organizations enabled with SCP functionality
- Management account access or delegated administrator permissions
- AWS Config enabled and the FMI-02 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-02" --recursive
```

## Test Setup

### 1. Check Organization Status
```bash
# Verify organization exists and get details
aws organizations describe-organization

# List organizational units
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id ROOT_ID
```

### 2. Create Test SCP (Non-Compliant)
```bash
# Create SCP without guardrail enforcement
aws organizations create-policy \
  --name "TestBedrockPolicy-NoGuardrail" \
  --description "Test SCP without guardrail enforcement" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ],
        "Resource": "*"
      }
    ]
  }'
```

### 3. List Existing SCPs
```bash
# List all Service Control Policies
aws organizations list-policies --filter SERVICE_CONTROL_POLICY

# Get details of existing SCPs
aws organizations describe-policy --policy-id POLICY_ID
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-02-guardrails-enforced
```

### 2. Check Evaluation Results
```bash
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-02-guardrails-enforced
```

### 3. Expected Results
**SCP without Guardrail Enforcement:**
- **Status:** NON_COMPLIANT
- **Reason:** SCP allows Bedrock actions without requiring guardrail conditions

## Testing Manual Remediation

### 1. Trigger Automatic Remediation
```bash
aws configservice start-remediation-execution \
  --config-rule-name fmi-02-guardrails-enforced \
  --resource-keys resourceType=AWS::Organizations::Policy,resourceId=POLICY_ID
```

### 2. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-02-guardrails-enforced
```

### 2. Re-evaluate After Remediation
```bash
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-02-guardrails-enforced

# Check evaluation results again
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-02-guardrails-enforced
```


## Test Scenarios

### Scenario 1: Missing Guardrail Condition
SCP allows Bedrock actions without guardrail requirements.
**Expected Result:** NON_COMPLIANT

### Scenario 2: Partial Guardrail Enforcement
SCP enforces guardrails for some but not all required actions.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Complete Guardrail Enforcement
SCP requires guardrails for all specified Bedrock actions.
**Expected Result:** COMPLIANT

### Scenario 4: Non-Bedrock SCP
SCP that doesn't contain Bedrock-related statements.
**Expected Result:** NOT_APPLICABLE

## Testing SCP Effectiveness

### 1. Test Guardrail Enforcement
```bash
# Try to invoke model without guardrail (should be denied)
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body '{"inputText": "Test without guardrail"}' \
  --content-type application/json \
  --accept application/json \
  output.json

# Try to invoke model with guardrail (should succeed)
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body '{"inputText": "Test with guardrail"}' \
  --content-type application/json \
  --accept application/json \
  --guardrail-identifier GUARDRAIL_ID \
  --guardrail-version "1" \
  output.json
```

## Cleanup Test Resources
```bash
# Detach test policies from OUs
aws organizations detach-policy --policy-id POLICY_ID --target-id OU_ID

# Delete test SCPs
aws organizations delete-policy --policy-id POLICY_ID_1
aws organizations delete-policy --policy-id POLICY_ID_2
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-02-guardrails-enforced`

## Troubleshooting

### Common Issues
1. **Organization not found:** Ensure AWS Organizations is enabled
2. **SCP creation fails:** Check management account permissions
3. **Policy attachment fails:** Verify OU exists and permissions
4. **Config rule not evaluating:** Verify SCPs exist in organization
5. **Lambda function errors:** Check CloudWatch logs

### Verification Steps
1. Confirm AWS Organizations is enabled
2. Verify SCP functionality is available
3. Check that SCPs contain Bedrock-related statements
4. Test SCP enforcement with actual API calls
5. Allow time for Config evaluation to complete
