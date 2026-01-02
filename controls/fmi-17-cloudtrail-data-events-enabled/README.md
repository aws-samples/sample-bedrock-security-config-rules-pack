# FMI-17: CloudTrail Data Events for Bedrock Resources

## Description
Validates that CloudTrail data events are properly configured to monitor specified AWS resource types, with a focus on comprehensive Bedrock activity monitoring. The control checks for active CloudTrail trails with advanced event selectors that capture data operations on the required resource types, ensuring complete audit coverage for sensitive AI/ML workloads.

**Config Resource Type:** `AWS::::Account`

## Data Privacy Notice
⚠️ **Important**: This control configures CloudTrail data events which capture detailed API activity including request parameters and response elements. Data events may contain sensitive information such as model inputs, outputs, and configuration details. Review your organization's data privacy and compliance requirements before enabling comprehensive data event logging.

## Prerequisites
- AWS Config must be enabled and recording account-level resources
- CloudTrail must be created and actively logging before running remediation
- IAM permissions for CloudTrail operations (see IAM Permissions Required section)
- Trail specified in SSM parameter `/bedrock-configrules/fmi-13/TrailName` must exist

## Related Controls
- **FMI-04:** Model Invocation Logging - Complementary application-level logging
- **FMI-14:** Guardrail CloudWatch Alarms - Uses CloudTrail events for alerting
- **FMI-15:** CloudWatch Alarms for Guardrail Events - Downstream monitoring based on CloudTrail data

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess CloudTrail data events configuration.

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `ResourceTypes` | String | Comma-separated list of AWS resource types that must have CloudTrail data events enabled | `AWS::Bedrock::Model,AWS::Bedrock::AsyncInvoke,AWS::Bedrock::Guardrail,AWS::Bedrock::AgentAlias,AWS::Bedrock::FlowAlias,AWS::Bedrock::InlineAgent,AWS::Bedrock::KnowledgeBase,AWS::Bedrock::PromptVersion,AWS::Bedrock::Session,AWS::Bedrock::FlowExecution` | Required |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `TrailName` | String | Name of the existing CloudTrail trail to configure | `dev-bedrock-data-trail` | Required |
| `ResourceTypes` | String | Comma-separated list of AWS resource types to configure for data events monitoring | `AWS::Bedrock::Model,AWS::Bedrock::AsyncInvoke,AWS::Bedrock::Guardrail,AWS::Bedrock::AgentAlias,AWS::Bedrock::FlowAlias,AWS::Bedrock::InlineAgent,AWS::Bedrock::KnowledgeBase,AWS::Bedrock::PromptVersion,AWS::Bedrock::Session,AWS::Bedrock::FlowExecution` | Required |
| `IncludeManagementEvents` | String | Whether to include management events in the trail configuration | `false` | Optional |

**Important**: The remediation function does NOT create S3 buckets or CloudTrail trails. It only updates existing, active trails with the required data event selectors. Ensure the trail specified in the remediation parameter `dev-bedrock-data-trail` exists before running remediation or replace `dev-bedrock-data-trail` with your trail name.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- At least one CloudTrail trail exists that is:
  - Multi-region (`IsMultiRegionTrail: true`)
  - Actively logging (`IsLogging: true`)
- Trail has advanced event selectors configured with:
  - Event category set to 'Data' (`eventCategory: Data`)
  - **ALL** required resource types specified in `resourceTypes` parameter are included (`resources.type`)
- No missing resource types from the required list

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No CloudTrail trails exist in the account
- All existing trails are either:
  - Not multi-region trails
  - Not actively logging
  - Inaccessible due to permissions
- **ANY** of the required resource types are missing from advanced event selectors
- Invalid resource types format in configuration parameters
- Error occurs while checking CloudTrail configuration

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for CloudTrail data events configuration.

### IAM Permissions Required
The remediation function requires the following IAM permissions:
- **CloudTrail**: `DescribeTrails`, `GetTrailStatus`, `GetEventSelectors`, `PutEventSelectors`
- **Config**: `PutEvaluations`
- **STS**: `GetCallerIdentity`

**Note**: The remediation function does NOT require S3 or CloudTrail creation permissions as it only updates existing trails.

### Remediation Behavior
When remediation is triggered, the function will:
1. **Validate the specified trail exists** and is actively logging
2. **Configure advanced event selectors** for each specified resource type on the existing trail
3. **Enable data events monitoring** for all required resource types
4. **Optionally include management events** if specified in parameters
5. **Remove duplicate selectors** to prevent configuration conflicts

