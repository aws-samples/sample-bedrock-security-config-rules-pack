# FMI-12 Guardrail Content Filters Testing Guide

## Overview
FMI-12 (Guardrail Content Filters) validates that Bedrock guardrails have comprehensive content filtering policies configured to block harmful, inappropriate, or unsafe content. This control ensures that guardrails have proper content policies with appropriate filter types, strength levels, and actions.

This document helps you understand how the FMI-12 control evaluates Bedrock guardrails for content filtering compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails
- AWS Config enabled and the FMI-12 control deployed
- Understanding of Bedrock guardrail content policies
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-12" --recursive
```


## Test Setup

### 1. Create Test Guardrail (Non-Compliant - No Content Policy)
```bash
# Create a test guardrail with minimal content policy (to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-content" \
  --description "Test guardrail without content filtering" \
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

### 2. Create Test Guardrail (Partially Compliant - Some Filters)
```bash
# Create a test guardrail with only some required content filters
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-partial-content" \
  --description "Test guardrail with partial content filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "VIOLENCE",
        "inputStrength": "LOW",
        "outputStrength": "LOW",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created partially compliant guardrail: $GUARDRAIL_ID_2"
```

### 3. Create Test Guardrail (Compliant - All Required Filters)
```bash
# Create a test guardrail with all required content filters
GUARDRAIL_ID_3=$(aws bedrock create-guardrail \
  --name "test-guardrail-complete-content" \
  --description "Test guardrail with complete content filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --content-policy-config '{
    "filtersConfig": [
      {
        "type": "SEXUAL",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "VIOLENCE",
        "inputStrength": "HIGH",
        "outputStrength": "HIGH",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "HATE",
        "inputStrength": "MEDIUM",
        "outputStrength": "MEDIUM",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "INSULTS",
        "inputStrength": "MEDIUM",
        "outputStrength": "MEDIUM",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created compliant guardrail: $GUARDRAIL_ID_3"
```


## Understanding Control Evaluation

### 1. List Created Guardrails
```bash
# List all guardrails to verify creation
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Get details of specific guardrails
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_2
aws bedrock get-guardrail --guardrail-identifier $GUARDRAIL_ID_3
```

### 2. Trigger Config Rule Evaluation
After creating test guardrails, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-12-guardrail-content-filters
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-12-guardrail-content-filters
```

### 4. Expected Results

**Non-Compliant Guardrails:**
- **Status:** NON_COMPLIANT
- **Reason:** Content policy not configured, missing required content filters, insufficient filter strength, or incorrect filter actions

**Compliant Guardrails:**
- **Status:** COMPLIANT
- **Reason:** All required content filters are properly configured with appropriate strength levels and actions

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create or update guardrails:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates or updates guardrails)
aws configservice start-remediation-execution \
  --config-rule-name fmi-12-guardrail-content-filters \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-12-guardrail-content-filters
```

### 3. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `ContentFilterGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have content policy configured with all specified content filters
- Each filter should have proper strength levels and input/output actions
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm the guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-12-guardrail-content-filters

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-12-guardrail-content-filters

```


## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has content policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom Content Filters
Set different `ContentFilters` parameter values to test custom filter types.
**Expected Result:** Compliance based on presence of specified filters

### Scenario 5: Different Strength Requirements
Test with `InputStrength=HIGH` and `OutputStrength=LOW` parameters.
**Expected Result:** Compliance based on meeting minimum strength requirements

### Scenario 6: Different Action Requirements
Test with `InputAction=NONE` and `OutputAction=BLOCK` parameters.
**Expected Result:** Compliance based on matching action requirements

## Testing Content Filter Functionality

### 1. Test Harmful Content (Should be Blocked)
```bash
# List all guardrails to verify remediation results
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Test model invocation with inappropriate content
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Generate violent or harmful content"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID \
  --guardrail-version "DRAFT" \
  blocked-test-output.json

# Check if the request was blocked
cat blocked-test-output.json
```

### 2. Test Acceptable Content (Should Pass)
```bash
# Test model invocation with acceptable content
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Write a professional business email"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID_3 \
  --guardrail-version "1" \
  acceptable-test-output.json

# Check the response
cat acceptable-test-output.json
```

## Cleanup Test Resources
```bash
# Delete test guardrails
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_2
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_3

# Note: If remediation updated an existing guardrail, you may need to manually revert changes
# or delete the guardrail if it was created by remediation



# Clean up test output files
rm -f blocked-test-output.json acceptable-test-output.json

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-12-guardrail-content-filters`

