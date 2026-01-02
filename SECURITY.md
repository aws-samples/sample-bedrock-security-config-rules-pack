# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it by emailing aws-security@amazon.com. Please do not report security vulnerabilities through public GitHub issues.

## IAM Roles and Permissions

| Control ID | Control Name | Role Name | Role Permissions |
|------------|--------------|-----------|------------------|
| FMI-01 | Bedrock Wildcard Permissions Prohibited | BedrockWildcardPermissionsProhibitedCheckExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, iam:ListRoles, iam:GetRole, iam:GetRolePolicy |
| FMI-01 | Bedrock Wildcard Permissions Prohibited | BedrockWildcardPermissionsProhibitedRemediationExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, iam:ListRoles, iam:GetRole, iam:GetRolePolicy, iam:PutRolePolicy, iam:CreatePolicy |
| FMI-01 | Bedrock Wildcard Permissions Prohibited | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-02 | Guardrails Enforced | GuardrailSCPCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, organizations:ListPolicies, organizations:DescribePolicy |
| FMI-02 | Guardrails Enforced | GuardrailSCPRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, organizations:ListPolicies, organizations:DescribePolicy, organizations:CreatePolicy, organizations:AttachPolicy |
| FMI-02 | Guardrails Enforced | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-03 | Tag-Based Access Enforced | TagBasedAccessCheckFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, iam:ListRoles, iam:GetRole, iam:GetRolePolicy |
| FMI-03 | Tag-Based Access Enforced | TagBasedAccessRemediationFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, iam:ListRoles, iam:GetRole, iam:GetRolePolicy, iam:PutRolePolicy |
| FMI-03 | Tag-Based Access Enforced | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-04 | Model Invocation Logging Enabled | ModelInvocationLogsFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:GetModelInvocationLoggingConfiguration, logs:DescribeLogGroups |
| FMI-04 | Model Invocation Logging Enabled | ModelInvocationLogsRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:GetModelInvocationLoggingConfiguration, logs:DescribeLogGroups, bedrock:PutModelInvocationLoggingConfiguration, s3:CreateBucket |
| FMI-04 | Model Invocation Logging Enabled | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-05 | Prompt Store Enabled | PromptStoreEnabledFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListPrompts, bedrock:GetPrompt |
| FMI-06 | Model Logs Encryption Enabled | BedrockModelLogsKmsCheckFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:GetModelInvocationLoggingConfiguration, kms:DescribeKey |
| FMI-06 | Model Logs Encryption Enabled | BedrockModelLogsKmsRemediationFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:GetModelInvocationLoggingConfiguration, kms:DescribeKey, kms:CreateKey, kms:CreateAlias |
| FMI-06 | Model Logs Encryption Enabled | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-07 | Knowledge Base Encryption Enabled | BedrockKnowledgeBasesKmsCheckFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase, kms:DescribeKey |
| FMI-07 | Knowledge Base Encryption Enabled | BedrockKnowledgeBasesKmsRemediationFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase, kms:DescribeKey, kms:CreateKey, bedrock:UpdateKnowledgeBase |
| FMI-07 | Knowledge Base Encryption Enabled | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-08 | Guardrail Encryption Enabled | BedrockGuardrailsKmsCheckFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, kms:DescribeKey |
| FMI-08 | Guardrail Encryption Enabled | BedrockGuardrailsKmsRemediationFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, kms:DescribeKey, kms:CreateKey, bedrock:UpdateGuardrail |
| FMI-08 | Guardrail Encryption Enabled | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-09 | VPC Endpoint Enabled | BedrockVpcEndpointCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, ec2:DescribeVpcEndpoints, ec2:DescribeVpcs |
| FMI-09 | VPC Endpoint Enabled | BedrockVpcEndpointRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, ec2:DescribeVpcEndpoints, ec2:DescribeVpcs, ec2:CreateVpcEndpoint, ec2:ModifyVpcEndpoint |
| FMI-10 | VPC Endpoint Policies Restricted | BedrockVpcEndpointPolicyCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, ec2:DescribeVpcEndpoints |
| FMI-10 | VPC Endpoint Policies Restricted | VpcEndpointPolicyRemediationFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, ec2:DescribeVpcEndpoints, ec2:ModifyVpcEndpoint |
| FMI-10 | VPC Endpoint Policies Restricted | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-11 | Guardrail Topic Filters Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-11 | Guardrail Topic Filters Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail |
| FMI-11 | Guardrail Topic Filters Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-12 | Guardrail Content Filters Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-12 | Guardrail Content Filters Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail |
| FMI-12 | Guardrail Content Filters Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-13 | Guardrail Word Filters Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-13 | Guardrail Word Filters Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail |
| FMI-13 | Guardrail Word Filters Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-14 | Guardrail PII Filters Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-14 | Guardrail PII Filters Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail |
| FMI-14 | Guardrail PII Filters Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-15 | Guardrail Contextual Grounding Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-15 | Guardrail Contextual Grounding Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail |
| FMI-15 | Guardrail Contextual Grounding Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-16 | Guardrail Automated Reasoning Enabled | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail |
| FMI-16 | Guardrail Automated Reasoning Enabled | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListGuardrails, bedrock:GetGuardrail, bedrock:UpdateGuardrail, bedrock:CreateAutomatedReasoningPolicy |
| FMI-16 | Guardrail Automated Reasoning Enabled | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-17 | CloudTrail Data Events Enabled | CloudTrailDataEventsFunctionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, cloudtrail:DescribeTrails, cloudtrail:GetEventSelectors |
| FMI-17 | CloudTrail Data Events Enabled | CloudTrailDataEventsRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, cloudtrail:DescribeTrails, cloudtrail:GetEventSelectors, cloudtrail:CreateTrail, s3:CreateBucket |
| FMI-17 | CloudTrail Data Events Enabled | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-18 | Guardrail Alarms Configured | LambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, cloudwatch:DescribeAlarms, bedrock:ListGuardrails |
| FMI-18 | Guardrail Alarms Configured | RemediationLambdaExecutionRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, cloudwatch:DescribeAlarms, bedrock:ListGuardrails, cloudwatch:PutMetricAlarm |
| FMI-18 | Guardrail Alarms Configured | AutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| FMI-19 | Guardrail Change Monitoring Enabled | GuardrailChangeMonitoringCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, events:ListRules, events:DescribeRule |
| FMI-19 | Guardrail Change Monitoring Enabled | GuardrailChangeMonitoringRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, events:ListRules, events:DescribeRule, events:PutRule, sns:CreateTopic |
| FMI-19 | Guardrail Change Monitoring Enabled | GuardrailChangeMonitoringAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| RAG-01 | Knowledge Base Approved Sources Only | KnowledgeBaseDataSourceCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListKnowledgeBases, bedrock:ListDataSources, bedrock:GetDataSource |
| RAG-01 | Knowledge Base Approved Sources Only | KnowledgeBaseDataSourceRemediationRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListKnowledgeBases, bedrock:ListDataSources, bedrock:GetDataSource, bedrock:UpdateDataSource |
| RAG-01 | Knowledge Base Approved Sources Only | RemediationAutomationRole | ssm:GetParameters, ssm:GetParameter, lambda:InvokeFunction, iam:PassRole |
| RAG-02 | Vector Database Encryption Enabled | VectorDbEncryptionCheckRole | logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, config:PutEvaluations, bedrock:ListKnowledgeBases, bedrock:GetKnowledgeBase, kms:DescribeKey |

## Sample Code Security Considerations

This sample code prioritizes demonstration and ease of deployment. For production environments, implement the security enhancements below.

## Production Security Enhancements

### 1. Remediation Lambda IAM Role Permissions
**Current**: Broad IAM permissions for comprehensive functionality demonstration
**Production Enhancement**: Implement least-privilege access patterns

```yaml
# Restrict IAM permissions to specific resources
- Effect: Allow
  Action:
    - iam:GetRole
    - iam:GetRolePolicy
  Resource: !Sub "arn:aws:iam::${AWS::AccountId}:role/bedrock-*"
- Effect: Allow
  Action:
    - iam:PutRolePolicy
  Resource: !Sub "arn:aws:iam::${AWS::AccountId}:role/bedrock-*"
  Condition:
    StringEquals:
      "iam:PolicyDocument": [specific policy document]
```

### 2. Lambda Environment Variable Encryption
**Current**: Lambda environment variables not encrypted with customer-managed KMS
**Production Enhancement**: Add KMS encryption for environment variables

```yaml
LambdaFunction:
  Type: AWS::Lambda::Function
  Properties:
    KmsKeyArn: !Ref LambdaKMSKey
    Environment:
      Variables:
        LOG_LEVEL: INFO

```

### 3. Lambda Dead Letter Queue Configuration
**Current**: Lambda functions missing Dead Letter Queue configuration
**Production Enhancement**: Add DLQ for error handling and debugging

```yaml
LambdaFunction:
  Type: AWS::Lambda::Function
  Properties:
    DeadLetterConfig:
      TargetArn: !GetAtt LambdaDLQ.Arn

# Dead Letter Queue
LambdaDLQ:
  Type: AWS::SQS::Queue
  Properties:
    QueueName: !Sub "${AWS::StackName}-lambda-dlq"
    MessageRetentionPeriod: 1209600  # 14 days
    KmsMasterKeyId: alias/aws/sqs
```


## Security Best Practices

### Access Control
- Replace inline IAM policies with managed policies for better governance
- Implement resource-based policies where appropriate
- Use IAM conditions to restrict access based on request context
- Regularly review and rotate access credentials

### Encryption
- Use customer-managed KMS keys for all encryption requirements
- Implement key rotation policies for customer-managed keys
- Encrypt Lambda environment variables containing sensitive data

### Network Security
- Deploy Lambda functions in private subnets
- Use VPC endpoints for AWS service communications
- Configure security groups with minimal required access
- Implement network ACLs for additional network-level controls

### Monitoring and Logging
- Enable CloudTrail for all API calls
- Configure CloudWatch alarms for security events
- Implement log aggregation and analysis
- Set up notifications for compliance violations

## Operational Security

### Change Management
- Implement proper change management for security control updates
- Test security controls in non-production environments first
- Document all security configuration changes
- Maintain rollback procedures for security updates

### Incident Response
- Configure Dead Letter Queues for Lambda error handling
- Set up SNS notifications for non-compliant resources
- Implement automated remediation where appropriate
- Maintain incident response procedures for security violations

### Compliance Monitoring
- Monitor AWS Config compliance dashboards regularly
- Review CloudWatch logs for security control execution
- Implement regular security assessments
- Maintain audit trails for compliance reporting

**Important**: This solution provides security controls but does not guarantee compliance. Organizations must assess their specific regulatory requirements and implement the mandatory fixes above.