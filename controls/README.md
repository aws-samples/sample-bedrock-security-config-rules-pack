# Bedrock Security Controls

This directory contains AWS Config rules and remediation functions for implementing security controls for Amazon Bedrock services. Each control is designed to enforce specific security best practices and compliance requirements for Foundation Model Invocation (FMI) and Retrieval-Augmented Generation (RAG) workloads.

## Available Controls

### Foundation Model Invocation (FMI) Controls

| Control ID | Name | Description | Resource Type |
|------------|------|-------------|---------------|
| **FMI-01** | Bedrock Wildcard Permissions Prohibited | Validates IAM roles follow least privilege principles for Bedrock access | `AWS::IAM::Role` |
| **FMI-02** | Guardrails Enforced | Ensures SCPs mandate guardrail usage for model invocations | `AWS::Organizations::Policy` |
| **FMI-03** | Tag-Based Access Enforced | Validates tag-based access control for Bedrock resources | `AWS::IAM::Role` |
| **FMI-04** | Model Invocation Logging Enabled | Ensures model invocation logging is properly configured | `AWS::Bedrock::*` |
| **FMI-05** | Prompt Store Enabled | Validates prompt store configuration and usage | `AWS::Bedrock::*` |
| **FMI-06** | Model Logs Encryption Enabled | Ensures model logs are encrypted with customer-managed KMS keys | `AWS::Bedrock::*` |
| **FMI-07** | Knowledge Base Encryption Enabled | Validates KMS encryption for Bedrock Knowledge Bases | `AWS::Bedrock::KnowledgeBase` |
| **FMI-08** | Guardrail Encryption Enabled | Ensures guardrails use customer-managed KMS encryption | `AWS::Bedrock::Guardrail` |
| **FMI-09** | VPC Endpoint Enabled | Validates VPC endpoint configuration for Bedrock | `AWS::EC2::VpcEndpoint` |
| **FMI-10** | VPC Endpoint Policies Restricted | Ensures VPC endpoint policies follow least privilege | `AWS::EC2::VpcEndpoint` |
| **FMI-11** | Guardrail Topic Filters Enabled | Validates topic filtering configuration in guardrails | `AWS::Bedrock::Guardrail` |
| **FMI-12** | Guardrail Content Filters Enabled | Ensures content filtering is properly configured | `AWS::Bedrock::Guardrail` |
| **FMI-13** | Guardrail Word Filters Enabled | Validates word filtering configuration | `AWS::Bedrock::Guardrail` |
| **FMI-14** | Guardrail PII Filters Enabled | Ensures PII filtering is enabled in guardrails | `AWS::Bedrock::Guardrail` |
| **FMI-15** | Guardrail Contextual Grounding Enabled | Validates contextual grounding configuration | `AWS::Bedrock::Guardrail` |
| **FMI-16** | Guardrail Automated Reasoning Enabled | Ensures automated reasoning is properly configured | `AWS::Bedrock::Guardrail` |
| **FMI-17** | CloudTrail Data Events Enabled | Validates CloudTrail logging for Bedrock data events | `AWS::CloudTrail::Trail` |
| **FMI-18** | Guardrail Alarms Configured | Ensures monitoring alarms are configured for guardrails | `AWS::CloudWatch::Alarm` |
| **FMI-19** | Guardrail Change Monitoring Enabled | Validates change monitoring for guardrail configurations | `AWS::Bedrock::Guardrail` |

### Retrieval-Augmented Generation (RAG) Controls

| Control ID | Name | Description | Resource Type |
|------------|------|-------------|---------------|
| **RAG-01** | Knowledge Base Approved Sources Only | Ensures only approved data sources are used in Knowledge Bases | `AWS::Bedrock::KnowledgeBase` |
| **RAG-02** | Vector Database Encryption Enabled | Validates encryption configuration for vector databases | `AWS::Bedrock::KnowledgeBase` |

## Common File Structure

Each control directory follows a standardized structure:

```
controls/[control-id]/
├── README.md                        # Control documentation and usage guide
├── TESTING.md                       # Testing procedures and examples
├── control-stack.yaml               # CloudFormation infrastructure template
├── lambda-function.py               # Evaluation logic for compliance checking
└── remediation-lambda-function.py   # Automatic remediation logic (if applicable)
```

### File Descriptions

- **README.md**: Comprehensive documentation including description, parameters, compliance conditions, and usage patterns
- **TESTING.md**: Step-by-step testing guide with CLI commands and expected results
- **control-stack.yaml**: CloudFormation template defining Lambda functions, IAM roles, and Config rules
- **lambda-function.py**: Python function that evaluates resource compliance against the control requirements
- **remediation-lambda-function.py**: Python function that automatically remediates non-compliant resources (when available)

## Testing

Each control includes a `TESTING.md` file with specific testing procedures, CLI commands, and cleanup instructions. 

To test a control:
1. Navigate to the control's directory
2. Follow the instructions in its `TESTING.md` file
3. Use the provided test scenarios and cleanup procedures

Example:
```bash
cd controls/fmi-01-bedrock-wildcard-permissions-prohibited
cat TESTING.md  # Review testing procedures
# Follow the documented test steps
```

## Common Operations

### Enable/Disable Controls

```bash
# Enable a control
aws ssm put-parameter \
  --name "/bedrock-configrules/global/DeployFMI01" \
  --value "true" \
  --overwrite

# Disable a control  
aws ssm put-parameter \
  --name "/bedrock-configrules/global/DeployFMI01" \
  --value "false" \
  --overwrite

# Redeploy to apply changes
./scripts/deploy.sh --bucket your-s3-bucket --update
```

### Debug Control Issues

```bash
# Check CloudWatch logs for a control
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/fmi01-BedrockWildcardPermissionsProhibited"

# View recent log events
aws logs filter-log-events \
  --log-group-name "/aws/lambda/fmi01-BedrockWildcardPermissionsProhibitedCheck" \
  --start-time $(date -d '1 hour ago' +%s)000

# Check Config rule status
aws configservice describe-config-rules \
  --config-rule-names "fmi-01-bedrock-bedrock-wildcard-permissions-prohibited"
```

### Update Control Parameters

```bash
# List current parameters for a control
aws ssm get-parameters-by-path --path "/bedrock-configrules/fmi-01" --recursive

# Update a parameter
aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-01/MaxWildcardActions" \
  --value "1" \
  --overwrite

# Trigger re-evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names "fmi-01-bedrock-bedrock-wildcard-permissions-prohibited"
```

When testing related controls, consider their interactions and ensure test resources don't conflict.

## Troubleshooting

### Control Not Evaluating
1. Check if control is enabled in SSM parameters
2. Verify AWS Config is enabled and recording
3. Check Lambda function logs for errors
4. Ensure test resources match control's resource type

### Parameter Issues
1. Verify parameter exists in SSM Parameter Store
2. Check parameter value format matches expected type
3. Ensure Lambda function has permission to read parameters

### Remediation Not Working
1. Check if remediation is enabled for the control
2. Verify remediation Lambda has required permissions
3. Review remediation logs for specific errors
4. Ensure resource is in a state that can be remediated

For detailed troubleshooting, refer to each control's README.md file.

