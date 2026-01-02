# FMI-03: Bedrock Access Restriction through Tags

## Description
Validates that IAM policies granting Bedrock permissions include tag-based access control conditions. Scans inline and managed policies attached to IAM roles, users, and groups to ensure Bedrock actions are restricted by `aws:ResourceTag/` conditions or direct tag key conditions.

**Config Resource Type:** `AWS::IAM::Role`

## Prerequisites
None - this control operates on existing IAM resources without additional prerequisites.

## Related Controls
- **FMI-02:** IAM Least Privilege - Complementary access control mechanism
- **FMI-12:** Guardrail IAM Condition - Uses similar tag-based access patterns

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess IAM policy compliance.

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredTagKeys` | String | Comma-separated list of tag keys that must be present in IAM policy conditions for Bedrock access | `Environment,Project,Owner` | Required |
| `MinTagConditions` | Number | Minimum number of tag conditions required in policies granting Bedrock access | `1` | Optional |
| `RolePathFilter` | String | IAM path prefix to filter roles for evaluation (e.g., `/test/` to only check test roles) | `/test/` | Optional |
| `RoleTagFilter` | String | Tag filter for roles in format `key=value` (e.g., `Environment=test`) | `Environment=test` | Optional |

### Remediation Function Parameters
Parameters used by the remediation Lambda function to fix non-compliant IAM policies.

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredTagKeys` | String | Comma-separated list of tag keys to add as conditions in IAM policies | `Environment,Project,Owner` | Required |
| `BedrockActions` | String | Comma-separated list of Bedrock actions to include in tag-based access policies | `bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels` | Optional |

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- IAM principal has Bedrock permissions with proper tag-based access control conditions
- Tag conditions include all required tag keys specified in the `RequiredTagKeys` parameter
- The number of tag conditions meets or exceeds the `MinTagConditions` requirement
- All policies granting Bedrock permissions include appropriate tag restrictions

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- IAM principal has Bedrock permissions without any tag-based access control conditions
- Tag conditions do not include all required tag keys
- The number of tag conditions is below the minimum requirement
- Some policies granting Bedrock permissions lack proper tag restrictions

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- IAM principal has no Bedrock permissions
- IAM principal does not match the specified path filter (if configured)
- IAM principal does not match the specified tag filter (if configured)

### IAM Permissions Required

**Evaluation Function Permissions:**
- **IAM Read**: `ListRoles`, `ListUsers`, `ListGroups`, `ListRolePolicies`, `ListUserPolicies`, `ListGroupPolicies`, `ListAttachedRolePolicies`, `ListAttachedUserPolicies`, `ListAttachedGroupPolicies`, `GetRole`, `GetRolePolicy`, `GetUserPolicy`, `GetGroupPolicy`, `GetPolicy`, `GetPolicyVersion`, `ListRoleTags`
- **Config**: `PutEvaluations`

**Remediation Function Permissions:**
- **IAM Read**: `GetRole`, `GetUser`, `GetGroup`, `GetRolePolicy`, `GetUserPolicy`, `GetGroupPolicy`, `GetPolicy`, `GetPolicyVersion`, `ListRolePolicies`, `ListUserPolicies`, `ListGroupPolicies`, `ListAttachedRolePolicies`, `ListAttachedUserPolicies`, `ListAttachedGroupPolicies`
- **IAM Write**: `PutRolePolicy`, `PutUserPolicy`, `PutGroupPolicy`, `CreatePolicy`, `AttachRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`
- **STS**: `GetCallerIdentity`

**SSM Automation Role Permissions:**
- **Lambda**: `InvokeFunction` (for remediation Lambda)

## Remediation Behavior
When remediation is triggered, the function will:
1. **Analyze existing policies** attached to the IAM entity
2. **Identify Bedrock permissions** without proper tag conditions
3. **Create or update policies** to include required tag-based access conditions
4. **Preserve existing permissions** while adding tag restrictions
5. **Use the specified tag keys** from the RequiredTagKeys parameter
