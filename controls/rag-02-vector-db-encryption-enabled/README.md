# RAG-02: Vector Database Encryption

## Description
Validates that vector databases used in RAG implementations are properly encrypted at rest and in transit. This control ensures that Bedrock Knowledge Base vector databases use customer-managed KMS keys for encryption to maintain security and compliance for AI operations.

**Config Resource Type:** `AWS::Bedrock::KnowledgeBase`

## Prerequisites
- Amazon Bedrock Knowledge Bases must be created
- Vector databases must be configured (OpenSearch Serverless, RDS, or S3 Vectors)
- Appropriate KMS key management and monitoring infrastructure

## Related Controls
- **RAG-01:** RAG Approved Sources - Complementary data source validation

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function to assess vector database encryption compliance:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredKmsKeyId` | String | Required KMS key ID for vector database encryption (use 'null' to allow any customer-managed key) | `null` | Optional |
| `AllowAWSManagedKeys` | String | Whether to allow AWS managed keys for vector database encryption | `false` | Optional |

### Remediation Function Parameters
This control does not include an automatic remediation function. Vector database encryption is immutable and requires manual recreation of the knowledge base with proper encryption settings.

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must customize all parameter values according to your environment before running remediation.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Knowledge base vector database uses customer-managed KMS key for encryption
- KMS key matches required key ID (if specified)
- AWS managed keys are used only when explicitly allowed
- Vector database storage type is supported (OpenSearch Serverless, RDS, S3 Vectors)
- Knowledge base status is "ACTIVE"

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- No knowledge bases configured in account
- Vector database does not have encryption configuration
- Vector database uses AWS managed key when customer-managed key is required
- KMS key does not match required key ID (if specified)
- Error accessing vector database encryption details
- Knowledge base not in "ACTIVE" status

### Not Applicable Conditions
A resource is considered **NOT_APPLICABLE** when:
- Knowledge base resource not found (may have been deleted)
- Resource type is not `AWS::Bedrock::KnowledgeBase`
- Vector database uses non-AWS storage type (control only applies to AWS storage types)

## Remediation Behavior
This control is **evaluation-only** and does not include automatic remediation capabilities. Vector database encryption is immutable and cannot be changed after creation.

**Manual Remediation Steps:**
1. **Identify non-compliant knowledge bases** from Config rule evaluation results
2. **Create new KMS key** (if needed) with appropriate permissions for Bedrock services
3. **Recreate knowledge base** with proper encryption configuration using customer-managed KMS key
4. **Update data sources** to point to the new encrypted knowledge base
5. **Delete old non-compliant knowledge base** after verifying functionality
