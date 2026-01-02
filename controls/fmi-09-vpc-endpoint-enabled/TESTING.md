# FMI-09: Bedrock PrivateLink Implementation - Testing Guide

## Overview
FMI-09 (Bedrock PrivateLink Implementation) validates the use of VPC endpoints for secure connectivity to Bedrock services. This control ensures Bedrock traffic remains within the AWS network.

## Prerequisites
- AWS CLI configured with appropriate permissions
- VPC with subnets and security groups configured
- Permissions to create/manage VPC endpoints
- AWS Config enabled and the FMI-09 control deployed

### Check Current Control Configuration
Before testing, check the actual SSM parameter names used by the control:

```bash
# List all parameters for this control to see actual parameter names
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-09" --recursive
```



## Test Setup

### 1. Check Existing VPC Configuration
```bash
# List VPCs
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,State]' --output table

# Get VPC ID for testing
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)
echo "Using VPC: $VPC_ID"

# List subnets in the VPC
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[*].[SubnetId,AvailabilityZone,CidrBlock]' --output table
```

### 2. Check Current VPC Endpoints
```bash
# List existing VPC endpoints for Bedrock
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.*.bedrock*" \
  --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State,VpcId]' \
  --output table
```

### 3. Create Test Security Group
```bash
# Create security group for VPC endpoints
SG_ID=$(aws ec2 create-security-group \
  --group-name bedrock-vpc-endpoint-sg \
  --description "Security group for Bedrock VPC endpoints" \
  --vpc-id $VPC_ID \
  --query 'GroupId' --output text)

# Allow HTTPS traffic from VPC CIDR
VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].CidrBlock' --output text)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 443 \
  --cidr $VPC_CIDR
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation (Non-Compliant State)
```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-09-vpc-endpoint-enabled
```

### 2. Check Evaluation Results
```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-09-vpc-endpoint-enabled
```

### 3. Expected Results (Before Creating Endpoints)
**VPC without Bedrock Endpoints:**
- **Status:** NON_COMPLIANT
- **Reason:** Required VPC endpoints for Bedrock services are missing

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the VPC and subnet parameters in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-09-vpc-endpoint-enabled`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the following values:
   - **DefaultVpcId**: Use the VPC ID from step 1 (use `echo $VPC_ID` to see the value)
   - **DefaultSubnetIds**: Use comma-separated subnet IDs from the VPC (get from the subnet list in step 1)
4. Click **Save**

### 2. Trigger Automatic Remediation
```bash
# Get VPC and subnet information
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)
SUBNET_IDS=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[0:2].SubnetId' \
  --output text | tr '\t' ',')


# Verify parameters are set correctly
aws ssm get-parameter --name "/bedrock-configrules/fmi-09/DefaultVpcId"
aws ssm get-parameter --name "/bedrock-configrules/fmi-09/DefaultSubnetIds"
```

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-09-vpc-endpoint-enabled \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Monitor Remediation Status
```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-09-vpc-endpoint-enabled
```

### 4. Verify VPC Endpoints Created
```bash
# List VPC endpoints for Bedrock services (after remediation)
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.*.bedrock*" \
  --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State,VpcId]' \
  --output table
```

### 5. Re-evaluate After Remediation
```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-09-vpc-endpoint-enabled

# Check evaluation result
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-09-vpc-endpoint-enabled

```

### 6. Expected Results (After Creating Endpoints)
**VPC with Bedrock Endpoints:**
- **Status:** COMPLIANT
- **Reason:** Required VPC endpoints for Bedrock services are properly configured

## Test Scenarios

### Scenario 1: Missing Required Service Endpoints
Create endpoint for only one service when both are required.
**Expected Result:** NON_COMPLIANT

### Scenario 2: Private DNS Disabled
Create endpoints without private DNS enabled.
**Expected Result:** NON_COMPLIANT

### Scenario 3: Wrong VPC
Create endpoints in different VPC than specified in filter.
**Expected Result:** NOT_APPLICABLE

## Testing VPC Endpoint Functionality

### Test Bedrock API Calls Through VPC Endpoint
Test VPC endpoint functionality by making Bedrock API calls from within the VPC to verify that traffic routes through the VPC endpoint instead of the internet gateway.

```bash
# Simple test to verify Bedrock API access through VPC endpoint
aws bedrock list-foundation-models --region us-east-1
```


## Cleanup Test Resources
```bash
# Delete VPC endpoints
ENDPOINT_IDS=($(aws ec2 describe-vpc-endpoints \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.*.bedrock*" \
  --query 'VpcEndpoints[*].VpcEndpointId' --output text))

if [ ${#ENDPOINT_IDS[@]} -gt 0 ]; then
  aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "${ENDPOINT_IDS[@]}"
else
  echo "No Bedrock VPC endpoints found to delete"
fi

# Delete security group
aws ec2 delete-security-group --group-id $SG_ID

# Note: Don't delete the VPC if it's being used for other resources
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-09-vpc-endpoint-enabled`

## Troubleshooting

1. **VPC endpoint creation fails:** Check subnet and security group configuration
2. **Service not available:** Verify Bedrock VPC endpoints are supported in the region
3. **DNS resolution issues:** Ensure private DNS is enabled
4. **Config rule not evaluating:** Verify VPC endpoints exist in the account
5. **Lambda function errors:** Check CloudWatch logs:
   ```bash
   aws logs describe-log-groups --log-group-name-prefix /aws/lambda/VPCEndpointCheck
   ```
