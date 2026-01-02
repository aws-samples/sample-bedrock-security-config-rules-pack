# FMI-13 Guardrail Word Policy Testing Guide

## Overview
FMI-13 (Guardrail Word Policy) validates that Bedrock guardrails have appropriate word filtering policies configured to block or flag specific words and phrases. This control ensures that guardrails have proper word policies with blocked words and/or managed word lists configured.

This document helps you understand how the FMI-13 control evaluates Bedrock guardrails for word policy compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails
- AWS Config enabled and the FMI-13 control deployed
- Understanding of Bedrock guardrail word policies
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see control's README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-13" --recursive
```


## Test Setup

### 1. Create Test Guardrail (Non-Compliant - No Word Policy)
```bash
# Create a test guardrail without word policy (but with minimal content policy to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-words" \
  --description "Test guardrail without word filtering" \
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

### 2. Create Test Guardrail (Partially Compliant - Only Blocked Words)
```bash
# Create a test guardrail with only blocked words (no managed word lists)
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-blocked-words-only" \
  --description "Test guardrail with only blocked words" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --word-policy-config '{
    "wordsConfig": [
      {
        "text": "inappropriate",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "text": "offensive",
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

### 3. Create Test Guardrail (Compliant - Words and Managed Lists)
```bash
# Create a test guardrail with both blocked words and managed word lists
GUARDRAIL_ID_3=$(aws bedrock create-guardrail \
  --name "test-guardrail-complete-words" \
  --description "Test guardrail with complete word filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --word-policy-config '{
    "wordsConfig": [
      {
        "text": "inappropriate",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "text": "offensive",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "text": "harmful",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      }
    ],
    "managedWordListsConfig": [
      {
        "type": "PROFANITY",
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
  --config-rule-names fmi-13-guardrail-word-filters
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-13-guardrail-word-filters
```

### 4. Expected Results

**Guardrail without Word Policy (test-guardrail-no-words):**
- **Status:** NON_COMPLIANT
- **Reason:** Word policy not configured in guardrail

**Guardrail with Only Blocked Words (test-guardrail-blocked-words-only):**
- **Status:** NON_COMPLIANT (if ManagedWordLists parameter is set)
- **Reason:** Missing managed word lists: PROFANITY

**Guardrail with Complete Word Policy (test-guardrail-complete-words):**
- **Status:** COMPLIANT
- **Reason:** All required blocked words and managed word lists are properly configured

**Guardrail with Wrong Actions (test-guardrail-wrong-word-actions):**
- **Status:** NON_COMPLIANT
- **Reason:** Blocked word issues: 'inappropriate': input action NONE, output action NONE; Managed word list issues: PROFANITY not enabled

**Guardrail with Empty Word Policy (test-guardrail-empty-words):**
- **Status:** NON_COMPLIANT
- **Reason:** Word policy exists but has no words or managed word lists configured

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create or update guardrails:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates or updates guardrails)
aws configservice start-remediation-execution \
  --config-rule-name fmi-13-guardrail-word-filters \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-13-guardrail-word-filters
```

### 3. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `WordPolicyGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have word policy configured with specified blocked words and managed word lists
- All words and lists should have proper input/output actions (BLOCK)
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm the new guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-13-guardrail-word-filters

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-13-guardrail-word-filters
```


## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has word policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom Blocked Words
Set different `BlockedWords` parameter values to test custom word filtering.
**Expected Result:** Compliance based on presence of specified words

### Scenario 5: Different Managed Word Lists
Test with different `ManagedWordLists` parameter values.
**Expected Result:** Compliance based on presence of specified managed lists

### Scenario 6: Different Input/Output Actions
Test with `InputAction=NONE` and `OutputAction=BLOCK` parameters.
**Expected Result:** Compliance based on matching action requirements

## Testing Word Filter Functionality

### 1. Test Blocked Words (Should be Blocked)
```bash
# List all guardrails to verify remediation results
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Test model invocation with blocked words
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "This content contains inappropriate language"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID_3 \
  --guardrail-version "DRAFT" \
  blocked-word-output.json

# Check if the request was blocked
cat blocked-word-output.json
```

### 2. Test Acceptable Language (Should Pass)
```bash
# Test model invocation with acceptable content
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Write a polite and respectful message"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID_3 \
  --guardrail-version "1"
```

## Cleanup Test Resources
```bash
# Delete test guardrails
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_2
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_3

# Note: If remediation updated an existing guardrail, you may need to manually revert changes
# or delete the guardrail if it was created by remediation



# No output files to clean up

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-13-guardrail-word-filters`
