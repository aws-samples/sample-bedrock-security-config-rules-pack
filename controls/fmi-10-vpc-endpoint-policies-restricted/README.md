                                                                                                                                                                            # FMI-10: Endpoint Policy Restrictions

## Description
Examines VPC endpoint policies for proper restrictions on Bedrock API actions by ensuring least-privilege access through the endpoints. This control validates that VPC endpoint policies don't grant excessive permissions and follow security best practices.

**Config Resource Type:** `AWS::EC2::VPCEndpoint`

## Prerequisites
- VPC endpoints for Bedrock services must exist (see FMI-09)
- Understanding of least privilege access principles

## Related Controls
- **FMI-09:** VPC Endpoint Enabled - Must be compliant for this control to apply
- **FMI-02:** IAM Least Privilege - Complementary access control mechanism

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `VpcEndpointPolicyConditionKey` | String | IAM condition key for VPC endpoint policy restrictions | `aws:PrincipalTag/Environment` | Required |
| `VpcEndpointPolicyConditionValues` | String | Comma-separated values for VPC endpoint policy condition | `dev,development` | Required |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `VpcEndpointPolicyConditionKey` | String | IAM condition key for VPC endpoint policy | `aws:PrincipalTag/Environment` | Required |
| `VpcEndpointPolicyConditionValues` | String | Comma-separated values for VPC endpoint policy condition | `dev,development` | Required |


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- All Bedrock VPC endpoints have `PolicyDocument` configured (not empty)
- Policy statements do not use wildcard principals (`*` or `AWS: *`)
- Policy statements do not use wildcard actions (`*` or `bedrock:*`)
- Policy includes proper `Condition` with required condition key and values
- Condition key matches `PolicyConditionKey` parameter (e.g., `aws:PrincipalTag/Environment`)
- Condition values match `PolicyConditionValues` parameter (e.g., `dev,development`)

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- VPC endpoint has no `PolicyDocument` (allows full access)
- Policy uses wildcard principals or actions
- Policy lacks proper `Condition` statements
- Policy missing required condition key or has incorrect values
- Policy parsing errors or invalid JSON format
- Rule configuration errors (missing required parameters)

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- No Bedrock VPC endpoints found in the account

## Remediation Behavior
When remediation is triggered, the function will:
1. **Identify non-compliant VPC endpoints** for Bedrock services
2. **Retrieve the current endpoint policy** for each non-compliant endpoint
3. **Add or update condition statements** with the required condition key and values
4. **Apply the updated policy** to restrict access appropriately
5. **Verify the policy update** was successful

The remediation ensures that VPC endpoint policies include proper condition statements to restrict access based on the configured condition key and values.
3. **Remove wildcard principals and actions** from policy statements
4. **Implement least privilege access** based on organizational requirements
5. **Validate policy syntax** and test effectiveness

