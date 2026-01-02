# FMI-11 Guardrail Topic Filters Testing Guide

## Overview
FMI-11 (Guardrail Topic Filters) ensures that Bedrock guardrails have topic-based filtering configured to prevent discussions of inappropriate or sensitive topics. This control validates that guardrails have proper topic policies configured with DENY actions for specified topics.

This document helps you understand how the FMI-11 control evaluates and remediates Bedrock guardrails for topic filtering compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails
- AWS Config enabled and the FMI-11 control deployed
- Understanding of Bedrock guardrail topic policies
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-11" --recursive
```


## Test Setup

### 1. Create Test Guardrail (Non-Compliant - No Topic Policy)
```bash
# Create a test guardrail without topic policy (but with minimal content policy to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-topics" \
  --description "Test guardrail without topic filtering" \
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

### 2. Create Test Guardrail (Partially Compliant - Some Topics)
```bash
# Create a test guardrail with only some required topics
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-partial-topics" \
  --description "Test guardrail with partial topic filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --topic-policy-config '{
    "topicsConfig": [
      {
        "name": "Violence",
        "definition": "Content related to violence or harm",
        "type": "DENY",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK",
        "examples": ["violent content example"]
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created partially compliant guardrail: $GUARDRAIL_ID_2"
```

### 3. Create Test Guardrail (Compliant - All Required Topics)
```bash
# Create a test guardrail with all required topic filters
GUARDRAIL_ID_3=$(aws bedrock create-guardrail \
  --name "test-guardrail-complete-topics" \
  --description "Test guardrail with complete topic filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --topic-policy-config '{
    "topicsConfig": [
      {
        "name": "Violence",
        "definition": "Content related to violence or harm",
        "type": "DENY",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK",
        "examples": ["violent content example"]
      },
      {
        "name": "HateSpeech",
        "definition": "Content containing hate speech or discrimination",
        "type": "DENY",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK",
        "examples": ["hate speech example"]
      },
      {
        "name": "SelfHarm",
        "definition": "Content related to self-harm or suicide",
        "type": "DENY",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK",
        "examples": ["self-harm content example"]
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
  --config-rule-names fmi-11-guardrail-topic-filters
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-11-guardrail-topic-filters
```

### 4. Expected Results

**Non-Compliant Guardrails:**
- **Status:** NON_COMPLIANT
- **Reason:** Topic policy not configured, missing required topic filters, topic action mismatches, or configuration issues

**Compliant Guardrails:**
- **Status:** COMPLIANT
- **Reason:** All required topic filters are properly configured with correct actions

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create or update guardrails:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates or updates guardrails)
aws configservice start-remediation-execution \
  --config-rule-name fmi-11-guardrail-topic-filters \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-11-guardrail-topic-filters
```

### 3. Verify Remediation Results
After remediation completes, verify the results:

```bash
# List all guardrails to verify remediation results
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table
```

### 4. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `TopicFilterGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have topic policy configured with all specified topics
- Each topic should have type "DENY" and proper input/output actions
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm the guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-11-guardrail-topic-filters

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-11-guardrail-topic-filters
```

## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has topic policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom Topic Filters
Set different `TopicFilters` parameter values to test custom topics.
**Expected Result:** Compliance based on presence of specified topics

### Scenario 5: Different Input/Output Actions
Test with `InputAction=NONE` and `OutputAction=BLOCK` parameters.
**Expected Result:** Compliance based on matching action requirements

## Testing Topic Filter Functionality

### 1. Test Inappropriate Topics (Should be Blocked)
```bash
# Test model invocation with inappropriate topic content
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Tell me how to commit acts of violence against others"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID\
  --guardrail-version "DRAFT" \
  blocked-topic-output.json

# Check if the request was blocked
cat blocked-topic-output.json
```

### 2. Test Acceptable Topics (Should Pass)
```bash
# Test model invocation with acceptable topic content
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Tell me about peaceful conflict resolution strategies"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID\
  --guardrail-version "DRAFT" \
  acceptable-topic-output.json

# Check the response
cat acceptable-topic-output.json
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
rm -f blocked-topic-output.json acceptable-topic-output.json

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-11-guardrail-topic-filters`
