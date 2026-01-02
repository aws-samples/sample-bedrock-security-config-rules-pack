# FMI-01: IAM Role Permissions Validation - Testing Guide

## Overview
FMI-01 (IAM Role Permissions Validation) identifies overly permissive IAM roles with wildcard Bedrock permissions and validates that roles follow least privilege principles. This control ensures that IAM policies use specific Bedrock actions instead of broad wildcard permissions.

This document helps you understand how the FMI-01 control evaluates IAM roles for least privilege compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- IAM permissions to create/modify roles and policies in `/test/` path
- AWS Config enabled and the FMI-01 control deployed
- Control configured with `RolePathFilter` set to `/test/` to limit evaluation scope
- If the control has `RoleTagFilter` configured, test roles must have matching tags

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-01" --recursive
```


## Test Setup

### 1. Create Test IAM Role (Non-Compliant - Wildcard Permissions)
```bash
# Create a test role with /test/ path prefix
aws iam create-role \
  --role-name TestBedrockRole-Wildcard \
  --path /test/ \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Add required tags if roleTagFilter is configured
aws iam tag-role --role-name TestBedrockRole-Wildcard --tags Key=Environment,Value=dev

# Attach a policy with wildcard Bedrock permissions (violates least privilege)
aws iam put-role-policy \
  --role-name TestBedrockRole-Wildcard \
  --policy-name BedrockWildcardPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "bedrock:*",
        "Resource": "*"
      }
    ]
  }'
```

### 2. Create Test IAM Role (Compliant - Specific Permissions)
```bash
# Create a compliant test role with /test/ path prefix
aws iam create-role \
  --role-name TestBedrockRole-Specific \
  --path /test/ \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Add required tags if roleTagFilter is configured
aws iam tag-role --role-name TestBedrockRole-Specific --tags Key=Environment,Value=dev

# Attach a policy with specific Bedrock permissions (follows least privilege)
aws iam put-role-policy \
  --role-name TestBedrockRole-Specific \
  --policy-name BedrockSpecificPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:GetFoundationModel"
        ],
        "Resource": "*"
      }
    ]
  }'
```

### 3. Create Test IAM Role (Non-Compliant - Multiple Wildcards)
```bash
# Create a test role with multiple wildcard permissions
aws iam create-role \
  --role-name TestBedrockRole-MultiWildcard \
  --path /test/ \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Add required tags if roleTagFilter is configured
aws iam tag-role --role-name TestBedrockRole-MultiWildcard --tags Key=Environment,Value=dev

# Attach policies with multiple wildcard permissions
aws iam put-role-policy \
  --role-name TestBedrockRole-MultiWildcard \
  --policy-name BedrockMultiWildcardPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "bedrock:*",
          "s3:*"
        ],
        "Resource": "*"
      }
    ]
  }'
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
After creating test roles, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-01-bedrock-bedrock-wildcard-permissions-prohibited
```

### 2. Check Evaluation Results
View the compliance status of your test roles:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-01-bedrock-bedrock-wildcard-permissions-prohibited
```

### 3. Expected Results

**Non-Compliant Role (TestBedrockRole-Wildcard):**
- **Status:** NON_COMPLIANT
- **Reason:** Role has wildcard Bedrock permissions (bedrock:*) violating least privilege

**Compliant Role (TestBedrockRole-Specific):**
- **Status:** COMPLIANT
- **Reason:** Role uses specific Bedrock actions following least privilege principles

**Non-Compliant Role (TestBedrockRole-MultiWildcard):**
- **Status:** NON_COMPLIANT
- **Reason:** Role has multiple wildcard permissions exceeding the allowed limit

**Role Outside Scope:**
- **Status:** NOT_APPLICABLE
- **Reason:** Role path does not match the configured filter

## Testing Manual Remediation

### 1. Trigger Manual Remediation
After identifying non-compliant roles, manually trigger remediation:

```bash
# First, get the full ARN of the role (needed for resourceId)
aws iam get-role --role-name TestBedrockRole-Wildcard --query 'Role.Arn' --output text

# Trigger remediation for a specific non-compliant role
aws configservice start-remediation-execution \
  --config-rule-name fmi-01-bedrock-bedrock-wildcard-permissions-prohibited \
  --resource-keys resourceType=AWS::IAM::Role,resourceId=arn:aws:iam::ACCOUNT-ID:role/test/TestBedrockRole-Wildcard
```

### 2. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-01-bedrock-bedrock-wildcard-permissions-prohibited
```

### 3. Verify Remediation Results
Check if the non-compliant role's policy was automatically updated:

```bash
# Check if the wildcard policy was replaced with specific actions
aws iam get-role-policy \
  --role-name TestBedrockRole-Wildcard \
  --policy-name BedrockWildcardPolicy
```

### 4. Expected Remediated Policy
After successful remediation, the policy should replace `bedrock:*` with specific actions like:
- `bedrock:InvokeModel`
- `bedrock:InvokeModelWithResponseStream`
- `bedrock:GetFoundationModel`
- `bedrock:ListFoundationModels`

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm the role is now compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-01-bedrock-bedrock-wildcard-permissions-prohibited
```

## Test Scenarios

### Scenario 1: Role with No Bedrock Permissions
Create a role with only S3 permissions (no Bedrock actions).
**Expected Result:** NOT_APPLICABLE

### Scenario 2: Role with Mixed Permissions
Create a policy with both specific and wildcard actions.
**Expected Result:** NON_COMPLIANT (due to wildcards)

### Scenario 3: Role Outside Scope
Create a role in `/prod/` path when filter is `/test/`.
**Expected Result:** NOT_APPLICABLE

### Scenario 4: Role with Allowed Wildcard Count
If `MaxWildcardActions` is set to 1, create a role with exactly 1 wildcard.
**Expected Result:** COMPLIANT

## Cleanup Test Resources
```bash
# Remove test policies
aws iam delete-role-policy \
  --role-name TestBedrockRole-Wildcard \
  --policy-name BedrockWildcardPolicy

aws iam delete-role-policy \
  --role-name TestBedrockRole-Specific \
  --policy-name BedrockSpecificPolicy

aws iam delete-role-policy \
  --role-name TestBedrockRole-MultiWildcard \
  --policy-name BedrockMultiWildcardPolicy

# Delete test roles
aws iam delete-role --role-name TestBedrockRole-Wildcard
aws iam delete-role --role-name TestBedrockRole-Specific
aws iam delete-role --role-name TestBedrockRole-MultiWildcard

# Delete additional test roles if created
aws iam delete-role-policy --role-name TestRole-NoBedrock --policy-name S3AccessPolicy 2>/dev/null || true
aws iam delete-role --role-name TestRole-NoBedrock 2>/dev/null || true
aws iam delete-role --role-name TestBedrockRole-OutsideScope 2>/dev/null || true

# Reset SSM parameters to defaults if modified during testing
aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-01/AllowedBedrockActions" \
  --value "bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels" \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-01/MaxWildcardActions" \
  --value "0" \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-01/RolePathFilter" \
  --value "/test/" \
  --type String \
  --overwrite
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-01-bedrock-bedrock-wildcard-permissions-prohibited`

### Verification Steps
1. Confirm test roles are created in the correct path (`/test/`)
2. **Check if roles need tags:** If the control has `roleTagFilter` configured, ensure test roles have matching tags
3. Verify roles have Bedrock permissions in their policies
4. Check that Config rule parameters match your test setup
5. Allow time for Config evaluation to complete (may take a few minutes)
6. **Check for NOT_APPLICABLE results:** Roles without matching path/tags will show as NOT_APPLICABLE
7. **Verify wildcard detection:** Ensure policies contain `bedrock:*` or other wildcards for non-compliant tests
