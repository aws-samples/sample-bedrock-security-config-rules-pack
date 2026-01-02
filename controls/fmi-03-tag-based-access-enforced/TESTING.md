# FMI-03: Bedrock Access Restriction through Tags - Testing Guide

## Overview
FMI-03 (Bedrock Access Restriction through Tags) validates that IAM policies granting Bedrock permissions include tag-based access control conditions. This control ensures that Bedrock resources can only be accessed when proper tag conditions are met.

This document helps you understand how the FMI-03 control evaluates IAM roles for tag-based access control compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- IAM permissions to create/modify roles and policies in `/test/` path
- AWS Config enabled and the FMI-03 control deployed
- Control configured with `RolePathFilter` set to `/test/` to limit evaluation scope
- If the control has `RoleTagFilter` configured, test roles must have matching tags

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-03" --recursive
```


## Test Setup

### 1. Create Test IAM Role (Non-Compliant)
```bash
# Create a test role with /test/ path prefix
aws iam create-role \
  --role-name TestBedrockRole-NonCompliant \
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

# Add required tags if roleTagFilter is configured (check control parameters)
aws iam tag-role --role-name TestBedrockRole-NonCompliant --tags Key=Environment,Value=dev

# Attach a policy with Bedrock permissions but no tag conditions
aws iam put-role-policy \
  --role-name TestBedrockRole-NonCompliant \
  --policy-name BedrockAccessPolicy \
  --policy-document '{
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

### 2. Create Test IAM Role (Compliant)
```bash
# Create a compliant test role with /test/ path prefix
aws iam create-role \
  --role-name TestBedrockRole-Compliant \
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
aws iam tag-role --role-name TestBedrockRole-Compliant --tags Key=Environment,Value=dev

# Attach a policy with Bedrock permissions and proper tag conditions
aws iam put-role-policy \
  --role-name TestBedrockRole-Compliant \
  --policy-name BedrockTagBasedAccessPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ],
        "Resource": "*",
        "Condition": {
          "StringEquals": {
            "aws:ResourceTag/Environment": "${aws:PrincipalTag/Environment}",
            "aws:ResourceTag/Project": "${aws:PrincipalTag/Project}"
          }
        }
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
  --config-rule-names fmi-03-bedrock-tag-based-access-enforced
```

### 2. Check Evaluation Results
View the compliance status of your test roles:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-03-bedrock-tag-based-access-enforced
```

### 3. Expected Results

**Non-Compliant Role (TestBedrockRole-NonCompliant):**
- **Status:** NON_COMPLIANT
- **Reason:** Role has Bedrock permissions without proper tag-based access control conditions

**Compliant Role (TestBedrockRole-Compliant):**
- **Status:** COMPLIANT
- **Reason:** Role has Bedrock permissions with appropriate tag conditions

**Role Outside Scope:**
- **Status:** NOT_APPLICABLE
- **Reason:** Role path does not match the configured filter

## Testing Manual Remediation

Since automatic remediation is disabled, you can manually trigger remediation for non-compliant resources.

### 1. Trigger Manual Remediation
After identifying non-compliant roles, manually trigger remediation:

```bash
# Trigger remediation for a specific non-compliant role
aws configservice start-remediation-execution \
  --config-rule-name fmi-03-bedrock-tag-based-access-enforced \
  --resource-keys resourceType=AWS::IAM::Role,resourceId=TestBedrockRole-NonCompliant
```

### 2. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-03-bedrock-tag-based-access-enforced
```

### 3. Verify Remediation Results
Check if the non-compliant role's policy was automatically updated:

```bash
# Check if the policy was updated with tag conditions
aws iam get-role-policy \
  --role-name TestBedrockRole-NonCompliant \
  --policy-name BedrockAccessPolicy
```

### 4. Expected Remediated Policy
After successful remediation, the policy should include tag conditions like `aws:ResourceTag/Environment`, `aws:ResourceTag/Project`, etc.

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm the role is now compliant:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-03-bedrock-tag-based-access-enforced
```

## Test Scenarios

### Scenario 1: Role with No Bedrock Permissions
Create a role with only S3 permissions (no Bedrock actions).
**Expected Result:** NOT_APPLICABLE

### Scenario 2: Role with Partial Tag Conditions
Create a policy with only 1 tag condition when 2+ are required.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Role Outside Scope
Create a role in `/prod/` path when filter is `/test/`.
**Expected Result:** NOT_APPLICABLE

## Cleanup Test Resources
```bash
# Remove test policies
aws iam delete-role-policy \
  --role-name TestBedrockRole-NonCompliant \
  --policy-name BedrockAccessPolicy

aws iam delete-role-policy \
  --role-name TestBedrockRole-Compliant \
  --policy-name BedrockTagBasedAccessPolicy

# Delete test roles (note: roles are in /test/ path)
aws iam delete-role --role-name TestBedrockRole-NonCompliant
aws iam delete-role --role-name TestBedrockRole-Compliant

# Delete additional test roles if created
aws iam delete-role-policy --role-name TestRole-NoBedrock --policy-name S3AccessPolicy 2>/dev/null || true
aws iam delete-role --role-name TestRole-NoBedrock 2>/dev/null || true
aws iam delete-role --role-name TestBedrockRole-OutsideScope 2>/dev/null || true

# Reset SSM parameters to defaults if modified during testing
aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-03/RequiredTagKeys" \
  --value "Environment,Project,Owner" \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-03/MinTagConditions" \
  --value "1" \
  --type String \
  --overwrite

aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-03/RolePathFilter" \
  --value "/test/" \
  --type String \
  --overwrite
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-03-bedrock-tag-based-access-enforced`

## Troubleshooting

### Common Issues
1. **Config rule not evaluating:** Verify AWS Config is enabled and recording IAM resources
2. **All roles showing NOT_APPLICABLE:** Check if `rolePathFilter` is too restrictive
4. **Unexpected compliance results:** Review the `requiredTagKeys` and `minTagConditions` parameters
5. **Lambda function errors:** Check CloudWatch logs for the Lambda functions:
   ```bash
   # Check evaluation function logs
   aws logs describe-log-groups --log-group-name-prefix /aws/lambda/TagBasedAccessCheck
   
   # Check remediation function logs  
   aws logs describe-log-groups --log-group-name-prefix /aws/lambda/TagBasedAccessRemediation
   
   # View recent log events (replace LOG_GROUP_NAME with actual log group)
   aws logs filter-log-events --log-group-name LOG_GROUP_NAME --start-time $(date -d '1 hour ago' +%s)000
   ```

### Verification Steps
1. Confirm test roles are created in the correct path (`/test/`)
2. **Check if roles need tags:** If the control has `roleTagFilter` configured, ensure test roles have matching tags
3. Verify roles have Bedrock permissions in their policies
4. Check that Config rule parameters match your test setup
5. Allow time for Config evaluation to complete (may take a few minutes)
6. **Check for NOT_APPLICABLE results:** Roles without matching path/tags will show as NOT_APPLICABLE