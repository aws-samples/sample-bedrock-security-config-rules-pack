# RAG-01: RAG Approved Sources

## Description
Ensures that RAG implementations only use approved and verified data sources for knowledge retrieval and generation. This control validates that Bedrock Knowledge Bases contain only authorized data sources with proper tagging and configuration to maintain security and compliance for AI operations.

**Config Resource Type:** `AWS::Bedrock::KnowledgeBase`

## Prerequisites
- Amazon Bedrock Knowledge Bases must be created
- Appropriate data source configuration and monitoring infrastructure

## Related Controls
- **RAG-02:** Vector Database Encryption - Complementary encryption validation

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess knowledge base approved sources compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredTags` | String | Comma-separated list of required tags in key=value format for S3 buckets | `BedrockApproved=true,Environment=dev` | Required |
| `ApprovedDataSourceTypes` | String | Comma-separated list of approved data source types | `S3` | Optional |
| `AllowedRegions` | String | Comma-separated list of allowed AWS regions for data sources | `null` | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredTags` | String | Comma-separated list of required tags in key=value format for S3 buckets | `BedrockApproved=true,Environment=dev` | Required |
| `AutoRemove` | String | Whether to automatically remove unauthorized data sources | `true` | Optional |
| `NotificationTopicArn` | String | SNS topic ARN for notifications about violations | `arn:aws:sns:us-east-1:123456789012:MyExampleSNSTopic` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Knowledge base has all required approval tags with correct values
- Data sources use only approved types (e.g., S3)
- Knowledge base is deployed in allowed regions (if specified)
- All data sources are from authorized and verified sources
- Knowledge base status is "ACTIVE"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No knowledge bases configured in account
- No knowledge bases match specified criteria (tags, regions)
- Missing required approval tags or incorrect tag values
- Uses unauthorized data source types
- Knowledge base deployed in restricted regions
- Contains data sources that are not approved or verified
- Knowledge base not in "ACTIVE" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Knowledge base resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::KnowledgeBase`

## Remediation Behavior
When remediation is triggered, the function will:
1. **Validate required parameters** and ensure RequiredTags is provided
2. **Identify non-compliant knowledge bases** that lack required approval tags
3. **Check data source types** against approved list and remove unauthorized sources if enabled
4. **Apply required tags** to knowledge bases that meet approval criteria
5. **Send notifications** about remediation actions taken (if SNS topic configured)

