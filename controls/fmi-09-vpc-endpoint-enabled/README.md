# FMI-09: Bedrock PrivateLink Implementation

## Description
Validates the use of VPC endpoints (PrivateLink) for secure connectivity to Bedrock services by checking for appropriate VPC endpoint configurations. This control ensures that Bedrock traffic remains within the AWS network and doesn't traverse the public internet.

**Config Resource Type:** `AWS::EC2::VPCEndpoint`

## Prerequisites
- VPC must be configured in the account
- Appropriate subnets and security groups must be available

## Related Controls
- **FMI-10:** VPC Endpoint Policy Restricted - Complementary endpoint policy control (requires FMI-09 to be compliant first)

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
The evaluation function does not use configurable parameters. It checks for VPC endpoints for the following Bedrock services:
- `com.amazonaws.{region}.bedrock`
- `com.amazonaws.{region}.bedrock-runtime`

### Remediation Function Parameters

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `EndpointVpcId` | String | Default VPC ID for creating endpoints | `null` | Required |
| `DefaultSubnetIds` | String | Comma-separated list of subnet IDs for VPC endpoints | `null` | Required |


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- At least one VPC endpoint exists for Bedrock services with state 'available'
- VPC endpoints are found for either:
  - `com.amazonaws.{region}.bedrock` service
  - `com.amazonaws.{region}.bedrock-runtime` service

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No VPC endpoints found for Bedrock services
- All existing Bedrock VPC endpoints are not in 'available' state
- Error occurs while checking VPC endpoints

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for Bedrock VPC endpoint configuration.

## Remediation Behavior
When remediation is triggered, the function will:
1. **Identify missing VPC endpoints** for Bedrock services
2. **Create VPC endpoints** in the specified VPC and subnets
3. **Configure private DNS** if required
4. **Apply security groups** to control access
5. **Set endpoint policies** for least privilege access

