# FMI-10: Endpoint Policy Restrictions - Testing Guide

## Overview
FMI-10 (Endpoint Policy Restrictions) examines VPC endpoint policies for proper restrictions on Bedrock API actions, ensuring least-privilege access through the endpoints.

## Prerequisites
- VPC endpoints for Bedrock services must exist (FMI-09 compliant)
- AWS CLI configured with appropriate permissions
- AWS Config enabled and the FMI-10 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-10" --recursive
```



## Test Setup

### 1. Find Existing Bedrock VPC Endpoints
```bash
# List Bedrock VPC endpoints
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.*.bedrock*" \
  --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,PolicyDocument]' \
  --output table

ENDPOINT_ID=$(aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.us-east-1.bedrock" \
  --query 'VpcEndpoints[0].VpcEndpointId' --output text)
```

### 2. Create Overly Permissive Policy (Non-Compliant)
```bash
# Apply overly permissive policy to VPC endpoint
aws ec2 modify-vpc-endpoint \
  --vpc-endpoint-id $ENDPOINT_ID \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "bedrock:*",
        "Resource": "*"
      }
    ]
  }'
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
```bash
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-10-vpc-endpoint-policy-restricted
```

### 2. Check Evaluation Results
```bash
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-10-vpc-endpoint-policy-restricted
```

### 3. Expected Results
**Overly Permissive Policy:**
- **Status:** NON_COMPLIANT
- **Reason:** VPC endpoint policy allows prohibited wildcard actions

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the policy parameters in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-10-vpc-endpoint-policy-restricted`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the policy configuration values as needed
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-10-vpc-endpoint-policy-restricted \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-10-vpc-endpoint-policy-restricted
```

### 4. Verify Remediation Results
Check if VPC endpoint policies were updated:

```bash
# Check VPC endpoint policy configuration
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.*.bedrock*" \
  --query 'VpcEndpoints[*].[VpcEndpointId,PolicyDocument]' \
  --output table
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-10-vpc-endpoint-policy-restricted

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-10-vpc-endpoint-policy-restricted
```

### 6. Expected Results (After Automatic Remediation)

**VPC Endpoints with Restrictive Policies:**
- **Status:** COMPLIANT
- **Reason:** VPC endpoint policies restrict access to specific Bedrock actions

## Test Scenarios

### Scenario 1: Wildcard Actions
Policy with `bedrock:*` actions.
**Expected Result:** NON_COMPLIANT

### Scenario 2: Missing Principal Restrictions
Policy with `"Principal": "*"` when restrictions required.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Specific Actions Only
Policy with only allowed specific actions.
**Expected Result:** COMPLIANT

## Cleanup Test Resources
```bash
# Reset to default policy if needed
aws ec2 modify-vpc-endpoint \
  --vpc-endpoint-id $ENDPOINT_ID \
  --reset-policy
```

## Troubleshooting
1. **No VPC endpoints found:** Ensure FMI-09 is compliant first
2. **Policy modification fails:** Check permissions
3. **Config rule not evaluating:** Verify endpoints exist
