# FMI-05: Prompt Store Utilization

## Description
Validates the proper configuration and usage of prompt stores for traceability and governance. Based on actual implementation, this control checks for the presence of "versioned prompts" in the account to ensure prompt versioning is being used for governance purposes.

**Config Resource Type:** `AWS::::Account`

## Prerequisites
- Amazon Bedrock service must be available in the region
- Prompt versioning feature must be supported and configured

## Related Controls
- **FMI-04:** Model Invocation Logging - Complements prompt store for comprehensive audit trail

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequireVersioning` | String | Whether prompt versioning must be enabled (true/false) | `true` | Optional |
| `MinPromptCount` | String | Minimum number of prompts required in the account | `1` | Optional |

### Remediation Function Parameters
This control does not include an automatic remediation function. Remediation must be performed manually based on the compliance findings.


**Note:** This control is evaluation-only and does not include automatic remediation capabilities.

## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Number of prompts found meets or exceeds `minPromptCount` parameter (default: 1)
- If `requireVersioning` is true (default), at least one prompt has non-DRAFT versions
- Prompt store is properly configured and accessible

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- Number of prompts found is less than `minPromptCount` parameter
- If `requireVersioning` is true, no versioned prompts found (all prompts are DRAFT only)
- Access denied to Bedrock prompt management (IAM permissions issue)
- Error occurs while evaluating Bedrock prompt store

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for Bedrock prompt store configuration.

**Note:** The specific requirements checked by this control are defined in the control's Lambda function implementation. Based on testing, it looks for "versioned prompts" in the account.

## Remediation Behavior
This control is evaluation-only and does not include automatic remediation capabilities. Manual remediation should be performed based on the compliance findings:

1. **Create versioned prompts** in Amazon Bedrock if none exist
2. **Enable prompt versioning** for existing prompts
3. **Ensure minimum prompt count** meets requirements
4. **Configure proper IAM permissions** for Bedrock prompt management
