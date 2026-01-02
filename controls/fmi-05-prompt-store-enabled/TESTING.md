# FMI-05: Prompt Store Utilization - Testing Guide

## Overview
FMI-05 (Prompt Store Utilization) validates that Amazon Bedrock prompt management features are being utilized for governance and traceability. This control checks for the presence and proper configuration of prompts in the account.

## Prerequisites
- AWS CLI configured with appropriate permissions
- Amazon Bedrock service available in the region
- Permissions to create and manage Bedrock prompts
- AWS Config enabled and the FMI-05 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-05" --recursive
```



## Test Setup

### 1. Check Current Prompts in Account
```bash
# List existing prompts in the account (should show no prompts initially)
aws bedrock-agent list-prompts --output table

# Expected output for new account:
# {
#     "promptSummaries": []
# }
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-05-prompt-store-enabled
```

### 2. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-05-prompt-store-enabled
```

### 3. Expected Results

**Account without Sufficient Prompts:**
- **Status:** NON_COMPLIANT
- **Reason:** Insufficient prompt store utilization (based on MinPromptCount parameter)

**Account with Sufficient Prompts:**
- **Status:** COMPLIANT
- **Reason:** Prompt store is properly utilized with required number of prompts

## Manual Remediation Steps

### 1. Create Test Prompt
```bash
# Create a simple test prompt
aws bedrock-agent create-prompt \
  --name "test-prompt-for-fmi05" \
  --description "Test prompt for FMI-05 compliance testing" \
  --default-variant "variant1" \
  --variants '[
    {
      "name": "variant1",
      "templateType": "TEXT",
      "templateConfiguration": {
        "text": {
          "text": "You are a helpful assistant. Please respond to: {{input}}"
        }
      },
      "modelId": "anthropic.claude-3-haiku-20240307-v1:0"
    }
  ]'
```

### 2. Create Prompt Version (for versioning requirement)
```bash
# Get the prompt ID from the creation response or list command
PROMPT_ID=$(aws bedrock-agent list-prompts --query 'promptSummaries[?name==`test-prompt-for-fmi05`].id' --output text)

# Create a version of the prompt
aws bedrock-agent create-prompt-version \
  --prompt-identifier $PROMPT_ID \
  --description "Version 1 of test prompt for compliance"
```

### 3. Verify Prompt Creation
```bash
# Check if prompts were created
aws bedrock-agent list-prompts

# Check prompt details (shows DRAFT version by default)
aws bedrock-agent get-prompt --prompt-identifier $PROMPT_ID

# Check specific versions (if versions were created)
aws bedrock-agent get-prompt --prompt-identifier $PROMPT_ID --prompt-version 1
aws bedrock-agent get-prompt --prompt-identifier $PROMPT_ID --prompt-version 2
```

### 4. Re-evaluate After Remediation
```bash
# Re-trigger evaluation to confirm compliance
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-05-prompt-store-enabled

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-05-prompt-store-enabled
```

## Test Scenarios

### Scenario 1: No Prompts in Account
Account without any prompts configured.
**Expected Result:** NON_COMPLIANT

### Scenario 2: Insufficient Prompt Count
Account with fewer prompts than the MinPromptCount parameter.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Sufficient Prompts
Account with prompts meeting or exceeding the MinPromptCount requirement.
**Expected Result:** COMPLIANT

### Scenario 4: Versioning Requirement
If RequireVersioning parameter is enabled, prompts must have versions.
**Expected Result:** Depends on versioning configuration

## Cleanup Test Resources
```bash

# Delete the test prompt
aws bedrock-agent delete-prompt --prompt-identifier $PROMPT_ID
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-05-prompt-store-enabled`
