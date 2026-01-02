# FMI-15 Guardrail Contextual Grounding Testing Guide

## Overview
FMI-15 (Guardrail Contextual Grounding) ensures that Bedrock guardrails have contextual grounding policies configured to prevent hallucinations and ensure factual accuracy. This control validates that guardrails have proper contextual grounding filters with appropriate thresholds and actions configured.

This document helps you understand how the FMI-15 control evaluates Bedrock guardrails for contextual grounding compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create/modify guardrails
- AWS Config enabled and the FMI-15 control deployed
- Understanding of Bedrock guardrail contextual grounding policies
- **IMPORTANT:** If testing with encrypted guardrails (FMI-08), ensure KMS key policy includes Lambda function permissions (see control's README.md Prerequisites section)

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-15" --recursive
```


## Test Setup

### 1. Create Test Guardrail (Non-Compliant - No Contextual Grounding Policy)
```bash
# Create a test guardrail without contextual grounding policy (but with minimal content policy to satisfy AWS requirements)
GUARDRAIL_ID_1=$(aws bedrock create-guardrail \
  --name "test-guardrail-no-grounding" \
  --description "Test guardrail without contextual grounding" \
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

### 2. Create Test Guardrail (Partially Compliant - Only Grounding Filter)
```bash
# Create a test guardrail with only grounding filter (no relevance filter)
GUARDRAIL_ID_2=$(aws bedrock create-guardrail \
  --name "test-guardrail-grounding-only" \
  --description "Test guardrail with only grounding filter" \
  --blocked-input-messaging "Input blocked by guardrail" \
  --blocked-outputs-messaging "Output blocked by guardrail" \
  --contextual-grounding-policy-config '{
    "filtersConfig": [
      {
        "type": "GROUNDING",
        "threshold": 0.8,
        "action": "BLOCK",
        "enabled": true
      }
    ]
  }' \
  --query 'guardrailId' --output text)

echo "Created partially compliant guardrail: $GUARDRAIL_ID_2"
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
  --config-rule-names fmi-15-guardrail-contextual-grounding
```

### 3. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-15-guardrail-contextual-grounding
```

### 4. Expected Results

**Non-Compliant Guardrails:**
- **Status:** NON_COMPLIANT
- **Reason:** Contextual grounding policy not configured, missing required filter types, threshold below minimum requirements, filters not enabled, or empty policy configuration

**Compliant Guardrails:**
- **Status:** COMPLIANT
- **Reason:** All required contextual grounding filters are properly configured with appropriate thresholds and actions

## Testing Automatic Remediation

### 1. Trigger Automatic Remediation
After identifying non-compliant state, trigger remediation to create a new compliant guardrail:

```bash
# Get account ID for remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation (creates new guardrail)
aws configservice start-remediation-execution \
  --config-rule-name fmi-15-guardrail-contextual-grounding \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 2. Monitor Remediation Progress
Check the remediation execution status:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-15-guardrail-contextual-grounding
```

### 3. Expected Remediation Outcomes
After successful remediation:
- If GuardrailName is specified, that guardrail will be updated if it exists, or created if it doesn't
- If GuardrailName is not specified, a new guardrail will be created with name format `ContextualGroundingGuardrail-YYYYMMDDHHMMSS`
- The guardrail should have contextual grounding policy configured with specified filter types
- All filters should have proper thresholds and actions (BLOCK)
- The guardrail should be tagged with `CreatedBy: AWSConfigRemediation`

### 4. Re-evaluate After Remediation
Trigger another evaluation to confirm the new guardrail makes the account compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-15-guardrail-contextual-grounding

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-15-guardrail-contextual-grounding
```

## Test Scenarios

### Scenario 1: No Guardrails in Account
Delete all guardrails to test empty account scenario.
**Expected Result:** NON_COMPLIANT - "No guardrails configured"

### Scenario 2: Guardrail with Specific Name Filter
Set `GuardrailName` parameter to test specific guardrail validation.
**Expected Result:** Depends on whether named guardrail has contextual grounding policy

### Scenario 3: Guardrail with Required Tags
Set `RequiredTags` parameter to test tag-based filtering.
**Expected Result:** Only guardrails with matching tags are evaluated

### Scenario 4: Custom Filter Types
Set different `FilterTypes` parameter values to test custom filter validation.
**Expected Result:** Compliance based on presence of specified filter types

### Scenario 5: Different Threshold Requirements
Test with `GroundingThreshold=0.9` and `RelevanceThreshold=0.8` parameters.
**Expected Result:** Compliance based on meeting minimum threshold requirements

### Scenario 6: Different Actions (NONE vs BLOCK)
Test with `FilterAction=NONE` parameter.
**Expected Result:** Compliance based on matching action requirements

## Testing Contextual Grounding Functionality

### 1. Test with Knowledge Base (Requires RAG Setup)
```bash
# Test contextual grounding with knowledge base
# Note: Requires a configured knowledge base and RAG setup
aws bedrock-runtime retrieve-and-generate \
  --input '{"text": "What is the capital of France based on the provided documents?"}' \
  --retrieve-and-generate-configuration '{
    "type": "KNOWLEDGE_BASE",
    "knowledgeBaseConfiguration": {
      "knowledgeBaseId": "YOUR_KB_ID",
      "modelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-express-v1",
      "generationConfiguration": {
        "guardrailConfiguration": {
          "guardrailId": "'$GUARDRAIL_ID_3'",
          "guardrailVersion": "1"
        }
      }
    }
  }' \
  grounding-test-output.json

# Check the response for grounding validation
cat grounding-test-output.json
```

### 2. Test Basic Model Invocation
```bash
# List all guardrails to verify remediation results
aws bedrock list-guardrails --query 'guardrails[*].[name,id,status]' --output table

# Test basic model invocation with contextual grounding guardrail
aws bedrock-runtime invoke-model \
  --model-id amazon.titan-text-express-v1 \
  --body $(echo '{"inputText": "Provide factual information about renewable energy"}' | base64) \
  --guardrail-identifier $GUARDRAIL_ID_2 \
  --guardrail-version "1" \
  grounding-basic-output.json

# Check the response
cat grounding-basic-output.json
```

## Cleanup Test Resources
```bash
# Delete test guardrails
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_1
aws bedrock delete-guardrail --guardrail-identifier $GUARDRAIL_ID_2

# Note: If remediation updated an existing guardrail, you may need to manually revert changes
# or delete the guardrail if it was created by remediation



# Clean up test output files
rm -f grounding-test-output.json grounding-basic-output.json

```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-15-guardrail-contextual-grounding`

