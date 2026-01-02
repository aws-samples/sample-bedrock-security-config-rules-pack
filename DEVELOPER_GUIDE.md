# Developer Guide - Bedrock Security Config Rules Pack

## Quick Setup

```bash
git clone <repo>
cd Bedrock-security-config-rules-pack
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
aws configure

# Edit parameters before deployment
# Customize parameters/ssm-parameters.yaml to configure:
# - Which controls to deploy (DeployFMI01, DeployFMI04, etc.)
# - Auto-remediation settings (EnableAutoRemediation)
# - Control-specific configurations

# Automated deployment - handles everything automatically
./scripts/deploy.sh --bucket your-unique-deployment-bucket
```

### ✨ Enhanced Deployment Script Features

The deployment script now provides:
- **🔍 Prerequisites Validation**: Automatically checks AWS CLI, credentials, and files
- **🏗️ SSM Stack Auto-Deployment**: Deploys parameters stack if not present
- **🪣 Smart S3 Management**: Creates bucket with proper regional configuration
- **📦 Lambda Packaging**: Handles all Lambda function packaging automatically
- **🛡️ Error Handling**: Comprehensive error messages and troubleshooting
- **📊 Deployment Summary**: Detailed reporting with AWS console links

## Architecture Overview

The solution uses a **two-stack architecture** with centralized parameter management:

### Stack Architecture
```
┌─────────────────────────────────────────┐
│         Parameter Stack                 │
│  parameters/ssm-parameters.yaml        │
│  ┌─────────────────────────────────────┐ │
│  │    SSM Parameter Store              │ │
│  │  • Global parameters               │ │
│  │  • Control-specific parameters     │ │
│  │  • Environment configurations      │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│         Main Stack                      │
│  main-template.yaml                     │
│  ┌─────────────────────────────────────┐ │
│  │    Nested Control Stacks           │ │
│  │  • Reads from SSM Parameter Store  │ │
│  │  • Deploys individual controls     │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Control Structure
Each security control is organized in its own directory:

```
controls/fmi-04-model-invocation-logging/
├── control-stack.yaml          # Complete CloudFormation template
├── lambda-function.py          # Compliance check function
├── remediation-lambda-function.py  # Remediation function
├── README.md                   # Control documentation and configuration
└── TESTING.md                  # Testing procedures and validation steps
```

## Adding New Control

### 1. Create Control Directory Structure
```bash
mkdir -p controls/fmi-XX-my-new-control
cd controls/fmi-XX-my-new-control
```

### 2. Create Lambda Functions
```python
# lambda-function.py (compliance check)
import boto3, json, logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = boto3.client('config')

def handler(event, context):
    invoking_event = json.loads(event.get('invokingEvent', '{}'))
    account_id = event.get('accountId')
    result_token = event.get('resultToken')
    
    try:
        # Your compliance check logic here
        compliance_type = 'COMPLIANT'  # or 'NON_COMPLIANT'
        annotation = "Check passed"
    except Exception as e:
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error: {str(e)}'
    
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': account_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': datetime.utcnow().isoformat()
    }
    
    if result_token:
        config.put_evaluations(Evaluations=[evaluation], ResultToken=result_token)
    
    return {'statusCode': 200}
```

```python
# remediation-lambda-function.py
import boto3, json, logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    try:
        # Your remediation logic here
        return {'statusCode': 200, 'message': 'Remediation successful'}
    except Exception as e:
        logger.error(f'Remediation failed: {str(e)}')
        return {'statusCode': 500, 'message': f'Error: {str(e)}'}
```

### 3. Create Unified Control Stack
```yaml
# control-stack.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'FMI-XX My New Control - Unified Stack'

Parameters:
  # Global parameters (read from SSM Parameter Store)
  TemplatesBucketName:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /bedrock-configrules/global/TemplatesBucketName
  ConfigRuleFrequency:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /bedrock-configrules/global/ConfigRuleFrequency
  EnableAutoRemediation:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /bedrock-configrules/global/EnableAutoRemediation
  
  # Control-specific parameters (add to SSM Parameter Store)
  MyControlParameter:
    Type: AWS::SSM::Parameter::Value<String>
    Default: /bedrock-configrules/fmi-xx/MyControlParameter

Resources:
  # IAM Role for Check Function
  CheckFunctionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "fmi-xx-check-role-${AWS::StackName}"
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        - arn:aws:iam::aws:policy/service-role/ConfigRole
      Policies:
        - PolicyName: CheckFunctionPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  # Add required permissions for your check
                  - bedrock:ListFoundationModels
                Resource: '*'

  # Check Lambda Function
  CheckFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "fmi-xx-check-${AWS::StackName}"
      Runtime: python3.9
      Handler: lambda-function.handler
      Role: !GetAtt CheckFunctionRole.Arn
      Code:
        S3Bucket: !Ref TemplatesBucketName
        S3Key: controls/fmi-xx-my-new-control/lambda-function.zip

  # Config Rule
  ConfigRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: !Sub "fmi-xx-my-new-control-${AWS::StackName}"
      Description: "My new control description"
      Source:
        Owner: CUSTOM_LAMBDA
        SourceIdentifier: !GetAtt CheckFunction.Arn
        SourceDetails:
          - EventSource: aws.config
            MaximumExecutionFrequency: !Ref ConfigRuleFrequency
            MessageType: ScheduledNotification

  # Lambda Permission for Config
  ConfigRulePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref CheckFunction
      Action: lambda:InvokeFunction
      Principal: config.amazonaws.com
      SourceAccount: !Ref AWS::AccountId

  # Remediation Function (if auto-remediation enabled)
  RemediationFunctionRole:
    Type: AWS::IAM::Role
    Condition: ShouldEnableRemediation
    Properties:
      RoleName: !Sub "fmi-xx-remediation-role-${AWS::StackName}"
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: RemediationPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  # Add required permissions for remediation
                  - bedrock:PutModelInvocationLoggingConfiguration
                Resource: '*'

  RemediationFunction:
    Type: AWS::Lambda::Function
    Condition: ShouldEnableRemediation
    Properties:
      FunctionName: !Sub "fmi-xx-remediation-${AWS::StackName}"
      Runtime: python3.9
      Handler: remediation-lambda-function.handler
      Role: !GetAtt RemediationFunctionRole.Arn
      Code:
        S3Bucket: !Ref TemplatesBucketName
        S3Key: controls/fmi-xx-my-new-control/remediation-lambda-function.zip

Conditions:
  ShouldEnableRemediation: !Equals [!Ref EnableAutoRemediation, "true"]

Outputs:
  CheckFunctionArn:
    Description: "ARN of the check function"
    Value: !GetAtt CheckFunction.Arn
  ConfigRuleName:
    Description: "Name of the Config rule"
    Value: !Ref ConfigRule
```

### 4. Add Parameters to SSM Parameter Store
Add your control's parameters to the SSM parameters template:

```yaml
# Add to parameters/ssm-parameters.yaml
  DeployFMIXXParam:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /bedrock-configrules/global/DeployFMIXX
      Type: String
      Value: 'false'
      Description: Deploy FMI-XX My New Control

  MyControlParameterParam:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /bedrock-configrules/fmi-xx/MyControlParameter
      Type: String
      Value: 'default-value'
      Description: Description of my control parameter
```

### 5. Update Main Template
Add your new control to the main template:

```yaml
# Add to main-template.yaml Parameters section:
DeployFMIXX:
  Type: AWS::SSM::Parameter::Value<String>
  Default: /bedrock-configrules/global/DeployFMIXX
  Description: "Deploy FMI-XX My New Control"

# Add to Conditions section:
ShouldDeployFMIXX: !Equals [!Ref DeployFMIXX, "true"]

# Add to Resources section:
FMIXXControlStack:
  Type: AWS::CloudFormation::Stack
  Condition: ShouldDeployFMIXX
  Properties:
    TemplateURL: !Sub "https://${TemplatesBucketName}.s3.amazonaws.com/controls/fmi-xx-my-new-control/control-stack.yaml"
```

### 6. Update Deploy Script
Add your control to the deployment script's packaging logic:

```bash
# Edit scripts/deploy.sh
# Add your control directory to the CONTROL_DIRS array or packaging logic
# This ensures your Lambda functions get zipped and uploaded to S3
```

### 7. Create Control Documentation

Create `README.md` and `TESTING.md` files in your control directory:

```bash
cd controls/fmi-xx-my-new-control

# Create README.md with control overview and parameters
cat > README.md << 'EOF'
# FMI-XX: My New Control

## Overview
Brief description of what this control validates.

## Parameters
- **MyControlParameter**: Description and valid values
- **EnableAutoRemediation**: Enable/disable automatic fixes
EOF

# Create TESTING.md with test procedures
cat > TESTING.md << 'EOF'
# Testing FMI-XX: My New Control

## Test Scenarios
1. **Compliant Resource**: Steps to create compliant resource and verify
2. **Non-Compliant Resource**: Steps to create violation and verify detection
3. **Remediation**: Test automatic remediation (if applicable)

## Commands
```bash
# Check rule status
aws configservice describe-config-rules --config-rule-names your-rule-name

# Test function
aws configservice start-config-rules-evaluation --config-rule-names your-rule-name
```
EOF
```

### 7. Deploy and Test Your Control

```bash
# Enable your control in parameters file
# Edit parameters/ssm-parameters.yaml and set:
# DeployFMIXXParam:
#   Value: 'true'

# Deploy with your control enabled
./scripts/deploy.sh --bucket your-deployment-bucket
```

## Parameter Management

### Parameter Structure

Parameters are organized hierarchically in SSM Parameter Store:

```
/bedrock-configrules/
├── global/                    # Shared across all controls
│   ├── EnableAutoRemediation  # Global remediation setting
│   ├── ConfigRuleFrequency    # How often rules evaluate
│   ├── NotificationTopicArn   # SNS topic for notifications
│   └── Deploy{ControlID}      # Enable/disable flags per control
├── fmi-04/                   # FMI-04 specific parameters
│   ├── LoggingDestination    # Control-specific settings
│   ├── LogGroupRetentionDays # ...
│   └── ...
└── ...
```

## Testing and Troubleshooting

### Debug Commands
```bash
# Check stack status
aws cloudformation describe-stacks --stack-name bedrock-security-configrules-pack

# Check Config rule status
aws configservice describe-config-rules --config-rule-names bedscr-fmi-04-model-invocation-logging

# Test Config rule evaluation
aws configservice start-config-rules-evaluation --config-rule-names bedscr-fmi-04-model-invocation-logging

# Validate CloudFormation template
aws cloudformation validate-template --template-body file://controls/fmi-04-model-invocation-logging/control-stack.yaml
```

### Common Issues

1. **Control not deploying**: Check that the control is enabled in parameters and conditions are correct
2. **Lambda function errors**: Check IAM permissions and environment variables
3. **Config rule not triggering**: Verify Lambda permissions and Config service setup
4. **Template validation errors**: Use `aws cloudformation validate-template` to check syntax