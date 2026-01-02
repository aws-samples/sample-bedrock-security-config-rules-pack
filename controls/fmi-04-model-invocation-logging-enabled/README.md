# FMI-04: Model Invocation Logging Enforcement

## Description
Ensures that all Bedrock model invocations are logged for audit and monitoring purposes by verifying that model invocation logging is enabled in Amazon Bedrock configuration with appropriate storage destinations. This control helps maintain transparency and auditability of AI model usage.

**Config Resource Type:** `AWS::::Account`

## Prerequisites
- Amazon Bedrock service must be available in the region
- Appropriate storage destinations (S3 bucket or CloudWatch Logs) must be configured for logging

## Related Controls
- **FMI-13:** CloudTrail Data Events - Provides additional logging context for Bedrock API calls
- **FMI-06:** Model Logs KMS - Ensures encryption of model invocation logs

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
The evaluation function does not use configurable parameters. It checks if model invocation logging is enabled and evaluates the configuration.

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `LoggingDestination` | String | Destination for model invocation logs (CloudWatch, S3, or Both) | `CloudWatch` | Optional |
| `LogGroupRetentionDays` | String | Number of days to retain logs in CloudWatch Logs | `90` | Optional |
| `InvocationLogsS3BucketName` | String | Name of the S3 bucket to store model invocation logs | `modelinvocationlogs` | Optional |
| `InvocationLogsLogGroupName` | String | Name of the log group to store model invocation logs | `/bedrock/modelinvocationlogs` | Optional |
| `ExistingLoggingRoleArn` | String | ARN of existing IAM role for Bedrock logging (optional) | `null` | Optional |

**Important:** The parameter values shown in the AWS Config console (such as `dev-modelinvocationlogs` for S3 bucket name) are **sample/example values only**. You must:
- **Replace S3 bucket names** with buckets that exist in your account or use unique names (S3 bucket names are globally unique)
- **Customize log group names** and retention periods according to your requirements
- **Verify IAM role ARNs** match your account and region
- **Update all parameter values** in the SSM Parameter Store paths (`/bedrock-configrules/fmi-04/{ParameterName}`) before running remediation

**Note:** These parameters are sourced from SSM Parameter Store with paths like `/bedrock-configrules/fmi-04/{ParameterName}` and can be configured through the CloudFormation template.


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Model invocation logging is enabled in Amazon Bedrock (has `loggingConfig`)
- At least one destination is properly configured:
  - CloudWatch log group is specified (`cloudWatchConfig.logGroupName`)
  - OR S3 bucket is specified (`s3Config.bucketName`)
- The logging configuration includes valid destination settings

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- Model invocation logging is not enabled (no `loggingConfig` found)
- Logging is configured but no valid destination is specified (neither CloudWatch nor S3)
- Error occurs while checking the logging configuration

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for Bedrock model invocation logging configuration.

## Remediation Behavior
When remediation is triggered, the function will:
1. **Check current logging configuration** for Amazon Bedrock
2. **Create necessary storage destinations** (S3 bucket or CloudWatch log group)
3. **Configure encryption** for log storage if required
4. **Enable model invocation logging** with the specified destinations
5. **Set appropriate retention policies** for log storage

