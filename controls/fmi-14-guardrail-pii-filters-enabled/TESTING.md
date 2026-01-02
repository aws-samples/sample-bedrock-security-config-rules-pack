# FMI-14 Guardrail Sensitive Information Testing Guide

## Overview
FMI-14 (Guardrail Sensitive Information) validates that Bedrock guardrails are configured to detect and block sensitive information like PII, financial data, and other confidential content. This control ensures that guardrails have proper sensitive information policies with PII entities and custom regex patterns configured.

This document helps you understand how the FMI-14 control evaluates Bedrock guardrails for sensitive information policy compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails
- AWS Config enabled and the FMI-14 control deployed
- Understanding of Bedrock guardrail sensitive information policies
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see control's README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-14" --recursive
```


## Test Setup

### 1. Create Test Guardrail (Non-Compliant - No Sensitive Information Policy)
```bash
# Create a test guardrail without sensitive information policy (but with minimal content policy to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-sensitive-info" \
  --description "Test guardrail without sensitive information filtering" \
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

### 2. Create Test Guardrail (Partially Compliant - Only PII Entities)
```bash
# Create a test guardrail with only PII entities (no custom regex patterns)
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-pii-only" \
  --description "Test guardrail with only PII entity filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --sensitive-information-policy-config '{
    "piiEntitiesConfig": [
      {
        "type": "EMAIL",
        "action": "BLOCK",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "PHONE",
        "action": "BLOCK",
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

### 3. Create Test Guardrail (Compliant - PII Entities and Custom Regex)
```bash
# Create a test guardrail with both PII entities and custom regex patterns
GUARDRAIL_ID_3=$(aws bedrock create-guardrail \
  --name "test-guardrail-complete-sensitive-info" \
  --description "Test guardrail with complete sensitive information filtering" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --sensitive-information-policy-config '{
    "piiEntitiesConfig": [
      {
        "type": "EMAIL",
        "action": "BLOCK",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "PHONE",
        "action": "BLOCK",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "CREDIT_DEBIT_CARD_NUMBER",
        "action": "BLOCK",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      },
      {
        "type": "US_SOCIAL_SECURITY_NUMBER",
        "action": "BLOCK",
        "inputEnabled": true,
        "outputEnabled": true,
        "inputAction": "BLOCK",
        "outputAction": "BLOCK"
      }
    ],
    "regexesConfig": [
      {
        "name": "SSN-Pattern",
        "description": "Social Security Number pattern",
        "pattern": "\\d{3}-\\d{2}-\\d{4}",
        "action": "BLOCK",
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
  --config-rule-names fmi-14-guardrail-pii-filters
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-14-guardrail-pii-filters
```

### 4. Expected Results

**Non-Compliant Guardrails:**
- **Status:** NON_COMPLIANT
- **Reason:** Sensitive information policy not configured, missing required PII entities or regex patterns, incorrect actions, or empty policy configuration

**Compliant Guardrails:**
- **Status:** COMPLIANT
- **Reason:** All required PII entities and custom regex patterns are properly configured with appropriate actions

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create or update guardrails:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates or updates guardrails)
aws configservice start-remediation-execution \
  --config-rule-name fmi-14-guardrail-pii-filters \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-14-guardrail-pii-filters
```

### 3. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `SensitiveInfoGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have sensitive information policy configured with specified PII entities and regex patterns
- All entities and patterns should have proper input/output actions (BLOCK)
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm the new guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-14-guardrail-pii-filters

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-14-guardrail-pii-filters
```

## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has sensitive information policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom PII Entities
Set different `PIIEntities` parameter values to test custom entity filtering.
**Expected Result:** Compliance based on presence of specified entities

### Scenario 5: Multiple Custom Regex Patterns
Set `RegexPattern1`, `RegexPattern2`, etc. to test multiple pattern validation.
**Expected Result:** Compliance based on presence of all specified patterns

### Scenario 6: Different Actions (ANONYMIZE vs BLOCK)
Test with `PIIAction=ANONYMIZE` and `InputAction=ANONYMIZE` parameters.
**Expected Result:** Compliance based on matching action requirements

## Testing Sensitive Information Filter Functionality

### 1. Test PII Detection (Should be Blocked)
```bash

# List all guardrails to verify remediation results
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Test model invocation with sensitive information
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "My email is john.doe@example.com and SSN is 123-45-6789"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID\
  --guardrail-version "DRAFT" \
  blocked-pii-output.json

# Check if the request was blocked
cat blocked-pii-output.json
```

### 2. Test Non-Sensitive Content (Should Pass)
```bash
# Test model invocation with no sensitive information
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Write a general business letter"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID \
  --guardrail-version "DRAFT" \
  acceptable-pii-output.json

# Check the response
cat acceptable-pii-output.json
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
rm -f blocked-pii-output.json acceptable-pii-output.json

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-14-guardrail-pii-filters`
