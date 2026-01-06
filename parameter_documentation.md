# Parameter Documentation for SSM Migration

This document contains all parameters used in control templates and their description.

| Control ID | Parameter Name | Type | Required | Default | Description | SSM Path | SSM Status |
|------------|----------------|------|----------|---------|-------------|----------|------------|
| GLOBAL | ConfigRuleFrequency | String | Yes | `` | Frequency at which the Config Rules will run | `/${ResourcePrefix}-${Environment}/global/ConfigRuleFrequency` | ✅ Exists |
| GLOBAL | EnableAutoRemediation | String | Yes | `` | Enable automatic remediation for non-compliant resources | `/${ResourcePrefix}-${Environment}/global/EnableAutoRemediation` | ✅ Exists |
| GLOBAL | GuardrailChangeNotificationTopicArn | String | Yes | `` | SNS topic ARN for receiving guardrail change notifications. When any guardrai... | `/${ResourcePrefix}-${Environment}/global/GuardrailChangeNotificationTopicArn` | ✅ Exists |
| GLOBAL | LambdaCodePrefix | String | Yes | `` | Prefix for Lambda code files in S3 bucket | `/${ResourcePrefix}-${Environment}/global/LambdaCodePrefix` | ✅ Exists |
| GLOBAL | NotificationTopicArn | String | No | `` | SNS topic ARN for violation notifications | `/${ResourcePrefix}-${Environment}/global/NotificationTopicArn` | ✅ Exists |
| GLOBAL | PrivateSubnetIds | CommaDelimitedList | No | `` | List of private subnet IDs for Lambda functions (leave empty to disable VPC) | `/${ResourcePrefix}-${Environment}/global/PrivateSubnetIds` | ✅ Exists |
| GLOBAL | RemediationRetryAttempts | String | Yes | `` | Maximum number of automatic remediation attempts | `/${ResourcePrefix}-${Environment}/global/RemediationRetryAttempts` | ✅ Exists |
| GLOBAL | RemediationRetrySeconds | String | Yes | `` | Seconds to wait between remediation attempts | `/${ResourcePrefix}-${Environment}/global/RemediationRetrySeconds` | ✅ Exists |
| GLOBAL | ResourcePrefix | String | Yes | `` | Prefix to use for resource names | `/${ResourcePrefix}-${Environment}/global/ResourcePrefix` | ✅ Exists |
| GLOBAL | SecurityGroupIds | CommaDelimitedList | No | `` | List of Security Group IDs for Lambda functions (leave empty to disable VPC) | `/${ResourcePrefix}-${Environment}/global/SecurityGroupIds` | ✅ Exists |
| GLOBAL | TargetOuId | String | Yes | `` | Organization Unit ID where the SCP should be applied | `/${ResourcePrefix}-${Environment}/global/TargetOuId` | ✅ Exists |
| GLOBAL | TemplatesBucketName | String | Yes | `` | Name of the S3 bucket containing Lambda code | `/${ResourcePrefix}-${Environment}/global/TemplatesBucketName` | ✅ Exists |
| GLOBAL | VpcId | String | No | `` | VPC ID for Lambda functions (leave empty to disable VPC) | `/${ResourcePrefix}-${Environment}/global/VpcId` | ✅ Exists |

| FMI-02 | BedrockActions | String | Yes | `` | Comma-separated list of Bedrock actions to include in tag-based access policies | `/${ResourcePrefix}-${Environment}/fmi-04/BedrockActions` | ✅ Exists |
| FMI-02 | MinTagConditions | String | Yes | `` | Minimum number of tag conditions required in policies | `/${ResourcePrefix}-${Environment}/fmi-01/MinTagConditions` | ✅ Exists |
| FMI-02 | RequiredTagKeys | String | Yes | `` | Comma-separated list of required tag keys for IAM policies | `/${ResourcePrefix}-${Environment}/fmi-01/RequiredTagKeys` | ✅ Exists |
| FMI-02 | RolePathFilter | String | Yes | `` | Optional IAM path prefix to filter roles for evaluation | `/${ResourcePrefix}-${Environment}/fmi-03/RolePathFilter` | ✅ Exists |
| FMI-02 | RoleTagFilter | String | Yes | `` | Optional tag filter for roles (format: key=value) | `/${ResourcePrefix}-${Environment}/fmi-03/RoleTagFilter` | ✅ Exists |
| FMI-03 | AllowedActions | String | Yes | `` | Comma-separated list of allowed Bedrock actions for least privilege policies | `/${ResourcePrefix}-${Environment}/fmi-08/AllowedActions` | ✅ Exists |
| FMI-03 | AllowedWildcardActions | String | Yes | `` | Comma-separated list of explicitly allowed wildcard actions | `/${ResourcePrefix}-${Environment}/fmi-05/AllowedWildcardActions` | ✅ Exists |
| FMI-03 | MaxWildcardActions | String | Yes | `` | Maximum number of wildcard actions allowed in policies | `/${ResourcePrefix}-${Environment}/fmi-05/MaxWildcardActions` | ✅ Exists |
| FMI-03 | ProhibitedActions | String | Yes | `` | Comma-separated list of prohibited Bedrock actions | `/${ResourcePrefix}-${Environment}/fmi-06/ProhibitedActions` | ✅ Exists |
| FMI-03 | RemediationActions | String | Yes | `` | Comma-separated list of remediation actions to perform | `/${ResourcePrefix}-${Environment}/fmi-09/RemediationActions` | ✅ Exists |
| FMI-03 | RequireResourceRestrictions | String | Yes | `` | Whether to require resource-level restrictions in policies | `/${ResourcePrefix}-${Environment}/fmi-07/RequireResourceRestrictions` | ✅ Exists |
| FMI-04 | ResourcePolicyRequiredTagKeys | String | Yes | `` | Comma-separated list of required tag keys for resource-based policies | `/${ResourcePrefix}-${Environment}/fmi-10/ResourcePolicyRequiredTagKeys` | ✅ Exists |
| FMI-05 | ExistingLoggingRoleArn | String | Yes | `` | ARN of existing IAM role for Bedrock logging (optional) | `/${ResourcePrefix}-${Environment}/fmi-05/ExistingLoggingRoleArn` | ✅ Exists |
| FMI-05 | InvocationLogsLogGroupName | String | Yes | `` | Name of the log group to store model invocation logs (Leave empty for default... | `/${ResourcePrefix}-${Environment}/fmi-11/InvocationLogsLogGroupName` | ✅ Exists |
| FMI-05 | InvocationLogsS3BucketName | String | Yes | `` | Name of the S3 bucket to store model invocation logs (Leave empty for default... | `/${ResourcePrefix}-${Environment}/fmi-11/InvocationLogsS3BucketName` | ✅ Exists |
| FMI-05 | LogGroupRetentionDays | String | Yes | `` | Log retention days for CloudWatch logs | `/${ResourcePrefix}-${Environment}/fmi-11/LogGroupRetentionDays` | ✅ Exists |
| FMI-05 | LoggingDestination | String | Yes | `` | Destination for model invocation logs | `/${ResourcePrefix}-${Environment}/fmi-11/LoggingDestination` | ✅ Exists |
| FMI-08 | DefaultSubnetIds | String | Yes | `` | Comma-separated subnet IDs | `/${ResourcePrefix}-${Environment}/fmi-19/DefaultSubnetIds` | ✅ Exists |
| FMI-08 | DefaultVpcId | String | Yes | `` | Default VPC ID for creating endpoints | `/${ResourcePrefix}-${Environment}/fmi-08/DefaultVpcId` | ✅ Exists |
| FMI-09 | VpcEndpointPolicyConditionKey | String | Yes | `` | IAM condition key for VPC endpoint policy restrictions | `/${ResourcePrefix}-${Environment}/fmi-19/VpcEndpointPolicyConditionKey` | ✅ Exists |
| FMI-09 | VpcEndpointPolicyConditionValues | String | Yes | `` | Comma-separated values for VPC endpoint policy condition | `/${ResourcePrefix}-${Environment}/fmi-19/VpcEndpointPolicyConditionValues` | ✅ Exists |
| FMI-10 | GuardrailContentFilterStrength | String | Yes | `` | Content filter strength for guardrails | `/${ResourcePrefix}-${Environment}/fmi-11/GuardrailContentFilterStrength` | ✅ Exists |
| FMI-11 | RequiredGuardrailArns | String | Yes | `` | Comma-separated list of required guardrail ARNs for SCP enforcement | `/${ResourcePrefix}-${Environment}/fmi-11/RequiredGuardrailArns` | ✅ Exists |
| FMI-15 | CloudTrailS3BucketName | String | Yes | `` | S3 bucket for CloudTrail logs | `/${ResourcePrefix}-${Environment}/fmi-12/CloudTrailS3BucketName` | ✅ Exists |
| FMI-15 | IncludeManagementEvents | String | Yes | `` | Include management events in CloudTrail | `/${ResourcePrefix}-${Environment}/fmi-12/IncludeManagementEvents` | ✅ Exists |
| FMI-15 | TrailName | String | Yes | `` | CloudTrail trail name for Bedrock data events | `/${ResourcePrefix}-${Environment}/fmi-12/TrailName` | ✅ Exists |
| FMI-16 | AlarmNamePrefix | String | No | `bedrock-guardrail` | Prefix for CloudWatch alarm names customization | `/${ResourcePrefix}-${Environment}/fmi-12/AlarmNamePrefix` | ✅ Exists |
| FMI-16 | AlarmThreshold | String | No | `0.0` | CloudWatch alarm threshold for guardrail events. Alarms trigger when metric v... | `/${ResourcePrefix}-${Environment}/fmi-12/AlarmThreshold` | ✅ Exists |
| FMI-16 | KmsKeyId | String | No | `` | KMS key ID for SNS topic encryption (leave empty to use default encryption) | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| FMI-16 | MetricFilterConfigurations | String | No | `[]` | JSON string containing array of metric filter configurations. Each configurat... | `/${ResourcePrefix}-${Environment}/fmi-11/MetricFilterConfigurations` | ✅ Exists |
| FMI-16 | MetricNamespace | String | No | `Custom/Bedrock/Guardrails` | CloudWatch metric namespace for guardrail metrics customization | `/${ResourcePrefix}-${Environment}/fmi-12/MetricNamespace` | ✅ Exists |
| FMI-16 | RequiredGuardrailTypes | String | No | `GUARDRAIL_INTERVENED,CONTENT_FILTER_SEXUAL,CONTENT_FILTER_VIOLENCE,TOPIC_INPUT_FINANCE` | Comma-separated list of required guardrail types to monitor (legacy parameter... | `/${ResourcePrefix}-${Environment}/fmi-12/RequiredGuardrailTypes` | ✅ Exists |
| FMI-16 | TopicNames | String | No | `Finance,Politics,Legal,Healthcare` | Comma-separated list of topic names to monitor for guardrail policies (legacy... | `/${ResourcePrefix}-${Environment}/fmi-12/TopicNames` | ✅ Exists |
| FMI-17 | EventBridgeRuleState | String | No | `ENABLED` | State of the EventBridge rule for guardrail change monitoring. Set to "ENABLE... | `/${ResourcePrefix}-${Environment}/fmi-12/EventBridgeRuleState` | ✅ Exists |
| FMI-17 | GuardrailChangeEventBridgeRuleName | String | No | `bedrock-guardrail-change-monitoring-account-level` | Account-level EventBridge rule name for monitoring ALL guardrail changes | `/${ResourcePrefix}-${Environment}/fmi-12/GuardrailChangeEventBridgeRuleName` | ✅ Exists |
| FMI-17 | GuardrailChangeLogRetentionDays | String | No | `30` | Log retention days for guardrail change monitoring logs | `/${ResourcePrefix}-${Environment}/fmi-12/GuardrailChangeLogRetentionDays` | ✅ Exists |
| FMI-17 | KmsKeyId | String | No | `` | KMS key ID for SNS topic encryption (leave empty if external topic doesn't us... | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| FMI-7.1 | KmsKeyId | String | Yes | `` | KMS key ID for encryption remediation | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| FMI-7.1 | RequiredKmsKeyIds | String | Yes | `` | Comma-separated list of required KMS key IDs for encryption | `/${ResourcePrefix}-${Environment}/rag-01/RequiredKmsKeyIds` | ✅ Exists |
| FMI-7.2 | KmsKeyId | String | Yes | `` | KMS key ID for encryption remediation | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| FMI-7.2 | RequiredKmsKeyIds | String | Yes | `` | Comma-separated list of required KMS key IDs for encryption | `/${ResourcePrefix}-${Environment}/rag-01/RequiredKmsKeyIds` | ✅ Exists |
| FMI-7.3 | KmsKeyId | String | Yes | `` | KMS key ID for encryption remediation | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| FMI-7.3 | RequiredKmsKeyIds | String | Yes | `` | Comma-separated list of required KMS key IDs for encryption | `/${ResourcePrefix}-${Environment}/rag-01/RequiredKmsKeyIds` | ✅ Exists |
| RAG-01 | AllowedRegions | String | No | `` | Comma-separated list of allowed AWS regions for data sources | `/${ResourcePrefix}-${Environment}/rag-01/AllowedRegions` | ✅ Exists |
| RAG-01 | ApprovedDataSourceTypes | String | No | `S3` | Comma-separated list of approved data source types | `/${ResourcePrefix}-${Environment}/rag-01/ApprovedDataSourceTypes` | ✅ Exists |
| RAG-01 | AutoRemoveUnauthorizedSources | String | No | `false` | Automatically remove unauthorized data sources | `/${ResourcePrefix}-${Environment}/rag-01/AutoRemoveUnauthorizedSources` | ✅ Exists |
| RAG-01 | KmsKeyId | String | No | `` | KMS key ID for SNS topic encryption (leave empty if external topic doesn't us... | `/${ResourcePrefix}-${Environment}/rag-01/KmsKeyId` | ✅ Exists |
| RAG-01 | RequireEncryption | String | No | `true` | Require data sources to be encrypted | `/${ResourcePrefix}-${Environment}/rag-01/RequireEncryption` | ✅ Exists |
| RAG-01 | RequiredTags | String | Yes | `` | Comma-separated list of required tags in key=value format for S3 buckets | `/${ResourcePrefix}-${Environment}/rag-01/RequiredTags` | ✅ Exists |
| RAG-02 | AllowAWSManagedKeys | String | Yes | `` | Whether to allow AWS managed keys for vector database encryption | `/${ResourcePrefix}-${Environment}/rag-02/AllowAWSManagedKeys` | ✅ Exists |
| RAG-02 | RequiredKmsKeyId | String | Yes | `` | KMS key ARN required for vector database encryption. If empty, any customer-m... | `/${ResourcePrefix}-${Environment}/rag-02/RequiredKmsKeyId` | ✅ Exists |

## Summary Statistics

- **Total Parameters Extracted**: 230
- **Parameters with Metadata Descriptions**: 43
- **Parameters Missing Descriptions**: 0
- **Parameters Missing in SSM**: 0
- **Total Controls**: 16
- **Global Parameters**: 13
- **Average Parameters per Control**: 13.6

## Parameters by Control

| Control ID | Parameter Count | Missing in SSM | Has Metadata |
|------------|-----------------|----------------|---------------|
| GLOBAL | 13 | 0 | 2 |

| FMI-02 | 5 | 0 | 5 |
| FMI-03 | 6 | 0 | 6 |
| FMI-04 | 1 | 0 | 1 |
| FMI-05 | 5 | 0 | 3 |
| FMI-08 | 2 | 0 | 0 |
| FMI-09 | 2 | 0 | 2 |
| FMI-10 | 1 | 0 | 1 |
| FMI-11 | 1 | 0 | 1 |
| FMI-15 | 3 | 0 | 3 |
| FMI-16 | 7 | 0 | 6 |
| FMI-17 | 4 | 0 | 1 |
| FMI-7.1 | 2 | 0 | 2 |
| FMI-7.2 | 2 | 0 | 2 |
| FMI-7.3 | 2 | 0 | 2 |
| RAG-01 | 6 | 0 | 4 |
| RAG-02 | 2 | 0 | 2 |
