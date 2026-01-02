# FMI-16 Guardrail Automated Reasoning Testing Guide

## Overview
FMI-16 (Guardrail Automated Reasoning) validates that Bedrock guardrails have automated reasoning capabilities enabled to improve decision-making and reduce bias. This control ensures that guardrails have proper automated reasoning policies with required policy configurations and confidence thresholds.

This document helps you understand how the FMI-16 control evaluates Bedrock guardrails for automated reasoning compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails and Automated Reasoning policies
- AWS Config enabled and the FMI-16 control deployed
- Understanding of Bedrock guardrail automated reasoning policies
- **Note:** Automated reasoning is an advanced Bedrock feature that may require specific model support
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see control's README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-16" --recursive
```


## Test Setup

### Prerequisites: Create an Automated Reasoning Policy
Before creating guardrails with automated reasoning, you need to create an automated reasoning policy:

```bash
# Option 1: Create an automated reasoning policy manually
# Note: This is a simplified example - actual policy creation requires more detailed configuration
POLICY_ARN=$(aws bedrock create-automated-reasoning-policy \
  --name "test-reasoning-policy" \
  --query 'policyArn' --output text)

echo "Created automated reasoning policy: $POLICY_ARN"

# Option 2: Let remediation create policy automatically
# If no policies are provided in the AutomatedReasoningPolicies parameter,
# the remediation function will automatically create a default policy
```

### 1. Create Test Guardrail (Non-Compliant - No Automated Reasoning Policy)
```bash
# Create a test guardrail without automated reasoning policy (but with minimal content policy to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-reasoning" \
  --description "Test guardrail without automated reasoning" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "LOW",
        "outputStrength": "LOW"
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created non-compliant guardrail: $GUARDRAIL_ID_1"
```

### 2. Create Test Guardrail (With Automated Reasoning Policy)
```bash
# Create a test guardrail with automated reasoning policy
# Note: You need to have created an automated reasoning policy first
# For this example, replace POLICY_ARN with your actual policy ARN
POLICY_ARN="arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/abcdef123456"

GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-with-reasoning" \
  --description "Test guardrail with automated reasoning policy" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "LOW",
        "outputStrength": "LOW"
      }
    ]
  }' \
  --automated-reasoning-policy-config '{
    "policies": ["'$POLICY_ARN'"],
    "confidenceThreshold": 0.8
  }' \
  --query 'guardrailId' --output text)

echo "Created guardrail with automated reasoning: $GUARDRAIL_ID_2"
```

## Understanding Control Evaluation

### 1. List Created Guardrails
```bash
# List all guardrails to verify creation
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Get details of specific guardrails
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_2

```

### 2. Trigger Config Rule Evaluation
After creating test guardrails, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-16-guardrail-automated-reasoning
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-16-guardrail-automated-reasoning
```

### 4. Expected Results

**Non-Compliant Guardrails:**
- **Status:** NON_COMPLIANT
- **Reason:** Automated reasoning policy not configured, missing required policies, confidence threshold below minimum, or policy configuration issues

**Compliant Guardrails:**
- **Status:** COMPLIANT
- **Reason:** All required automated reasoning policies and confidence threshold are properly configured

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the `AutomatedReasoningPolicies` in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-16-guardrail-automated-reasoning`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the **AutomatedReasoningPolicies** value:
   - **Option A:** Use existing policy ARN (e.g., `arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/abc123def456`)
   - **Option B:** Leave empty or set to `null` to test automatic policy creation
4. Click **Save**

### 2. Test Automatic Policy Creation
To test the automatic policy creation feature, leave the `AutomatedReasoningPolicies` parameter empty.


### 3. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create a new compliant guardrail:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates new guardrail)
aws configservice start-remediation-execution \
  --config-rule-name fmi-16-guardrail-automated-reasoning \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 4. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-16-guardrail-automated-reasoning
```

### 5. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `AutomatedReasoningGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have automated reasoning policy configured with specified policies
- The confidence threshold should meet minimum requirements
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 6. Re-evaluate After Remediation
Trigger another evaluation to confirm the new guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-16-guardrail-automated-reasoning

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-16-guardrail-automated-reasoning

```

## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has automated reasoning policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom Required Policies
Set different `AutomatedReasoningPolicies` parameter values to test custom policy validation.
**Expected Result:** Compliance based on presence of specified policies

### Scenario 5: Different Confidence Thresholds
Test with `MinConfidenceThreshold=0.9` parameter.
**Expected Result:** Compliance based on meeting minimum confidence requirements


## Cleanup Test Resources
```bash
# Delete test guardrails
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_2
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_3

# Note: If remediation updated an existing guardrail, you may need to manually revert changes
# or delete the guardrail if it was created by remediation



# Clean up test output files
rm -f reasoning-test-output.json reasoning-validation-output.json

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-16-guardrail-automated-reasoning`

