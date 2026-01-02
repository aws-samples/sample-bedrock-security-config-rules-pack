# FMI-01: IAM Role Permissions Validation

## Description
Identifies overly permissive IAM roles with wildcard Bedrock permissions and validates that roles follow least privilege principles for Bedrock access. This control checks for excessive permissions like `bedrock:*` and ensures specific actions are used instead of broad permissions.

**Config Resource Type:** `AWS::IAM::Role`

## Prerequisites
None - this control operates on existing IAM resources without additional prerequisites.

## Related Controls
- **FMI-01:** Tag-based Access Control - Complementary access control mechanism
- **FMI-12:** Guardrail IAM Condition - Uses similar IAM policy validation patterns

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to determine IAM roles with `bedrock:*`:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `MaxWildcardActions` | Number | Maximum number of wildcard actions allowed in policies | `0` | Optional |
| `AllowedWildcardActions` | String | Comma-separated list of explicitly allowed wildcard actions | `bedrock:Get*,bedrock:List*,bedrock:Describe*` | Optional |
| `ProhibitedActions` | String | Comma-separated list of prohibited Bedrock actions | `bedrock:DeleteCustomModel` | Optional |
| `RequireResourceRestrictions` | Boolean | Whether to require resource-level restrictions in policies | `false` | Optional |
| `RolePathFilter` | String | Filter roles by path prefix (e.g., `/custom/`) | `/test/` | Optional |
| `RoleTagFilter` | String | Filter roles by tags (format: key=value;key2=value2) | `Environment=dev` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RemediationActions` | String | Comma-separated list of remediation actions to perform | `replace_wildcards` | Optional |
| `AllowedActions` | String | Comma-separated list of allowed Bedrock actions for replacement | `bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels,bedrock:CreateModelCustomizationJob` | Optional |
| `ProhibitedActions` | String | Comma-separated list of prohibited actions to remove | `bedrock:DeleteCustomModel` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- IAM role has Bedrock permissions AND follows all least privilege principles:
  - Number of disallowed wildcard actions (like `bedrock:*` or `*`) does not exceed the `maxWildcardActions` parameter (default: 0)
  - Does not contain any actions from the `prohibitedActions` list (default includes `bedrock:DeleteCustomModel`, `bedrock:PutModelInvocationLoggingConfiguration`)
  - If `requireResourceRestrictions` is enabled, policies must include specific resource ARNs instead of using `*` for resources
  - Only uses wildcard actions that are explicitly listed in `allowedWildcardActions` parameter

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- IAM role has Bedrock permissions BUT violates least privilege principles:
  - Uses full wildcard (`*`) which grants unrestricted access to all AWS services
  - Uses Bedrock service wildcard (`bedrock:*`) which grants unrestricted access to all Bedrock actions
  - Contains prohibited actions like `bedrock:DeleteCustomModel` or `bedrock:PutModelInvocationLoggingConfiguration`
  - Exceeds the maximum allowed number of wildcard actions
  - Lacks proper resource restrictions when `requireResourceRestrictions` is set to true
  - Has evaluation errors during policy analysis

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- IAM role has no Bedrock permissions at all (no actions starting with `bedrock:`)
- Role is an AWS managed service role (path starts with `/aws-service-role/` or `/service-role/`)
- Role doesn't match the specified `rolePathFilter` (if configured)
- Role doesn't match the specified `roleTagFilter` (if configured)
- Role name cannot be determined from the configuration item

**Note:** The specific requirements checked by this control are defined in the control's Lambda function implementation. Refer to the actual control code for precise compliance criteria.

## Remediation Behavior
When remediation is triggered, the function will:
1. **Analyze inline policies** attached to the IAM entity for Bedrock permissions
2. **Replace wildcard actions** (`bedrock:*` or `*`) with specific allowed Bedrock actions
3. **Remove prohibited actions** from policy statements
4. **Add MFA conditions** for administrative Bedrock actions (if configured)
5. **Preserve existing permissions** while applying least privilege principles

**Note:** The remediation only modifies policies that contain Bedrock permissions and preserves policies without Bedrock actions unchanged.

## Compliance Mappings
- **AWS Well-Architected Framework:** Security Pillar - Identity and Access Management
- **ISO 27001:** Access Control Management
- **NIST AI RMF:** Govern 1.4 (Document and Control)
