# Deployment Guide - Bedrock Security Config Rules Pack

This guide provides comprehensive instructions for deploying the Bedrock Security Config Rules Pack using the enhanced automated deployment script.

## 🚀 Overview

The deployment script has been significantly enhanced to provide a streamlined, automated deployment experience:

- **Automatic Prerequisites Validation**: Validates AWS CLI, credentials, and required files
- **SSM Parameters Stack Auto-Deployment**: Automatically deploys the parameters stack if not present
- **Smart S3 Bucket Management**: Creates buckets with proper regional configuration
- **Enhanced Error Handling**: Comprehensive error messages and troubleshooting guidance
- **Deployment Summary**: Detailed reporting with AWS console links

## 📋 Prerequisites

### Automatic Validation
The deployment script automatically validates:
- ✅ AWS CLI installation and availability
- ✅ AWS credentials configuration and validity
- ✅ Required template files existence
- ✅ Controls directory structure

### Manual Setup Required
- **AWS Config Service**: Must be enabled in your target account
- **IAM Permissions**: Appropriate permissions for CloudFormation operations
- **S3 Bucket Name**: Choose a globally unique bucket name

### Required IAM Permissions

The deployment requires the following IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudFormationOperations",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:GetTemplate",
        "cloudformation:ListStacks",
        "cloudformation:ValidateTemplate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3Operations",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutBucketVersioning",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    },
    {
      "Sid": "SSMOperations",
      "Effect": "Allow",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "ssm:DeleteParameter",
        "ssm:DescribeParameters"
      ],
      "Resource": "arn:aws:ssm:*:*:parameter/bedrock-configrules/*"
    },
    {
      "Sid": "IAMOperations",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "LambdaOperations",
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "lambda:InvokeFunction"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigOperations",
      "Effect": "Allow",
      "Action": [
        "config:PutConfigRule",
        "config:DeleteConfigRule",
        "config:DescribeConfigRules",
        "config:PutRemediationConfigurations",
        "config:DeleteRemediationConfiguration"
      ],
      "Resource": "*"
    },
    {
      "Sid": "STSOperations",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🚀 Selective Control Packaging

The deployment script now intelligently packages only the Lambda functions for controls that are enabled in your SSM Parameter Store configuration. This provides several benefits:

### Benefits
- **⚡ Faster Deployments**: Only packages and uploads necessary Lambda functions
- **💾 Reduced Storage**: Smaller S3 storage footprint for Lambda packages
- **🔧 Efficient Updates**: Only processes controls you're actually using
- **📊 Clear Visibility**: Shows which controls are enabled/disabled during deployment

### How It Works
1. **Parameter Check**: Script reads `/bedrock-configrules/global/Deploy{ControlID}` parameters
2. **Selective Packaging**: Only packages Lambda functions for controls where parameter = "true"
3. **Fallback Safety**: If no controls are enabled or parameters can't be read, packages all controls
4. **Override Option**: Use `--package-all` flag to package all controls regardless of status

### Examples
```bash
# Enable specific controls
aws ssm put-parameter --name "/bedrock-configrules/global/DeployFMI04" --value "true" --overwrite
aws ssm put-parameter --name "/bedrock-configrules/global/DeployFMI11" --value "true" --overwrite
aws ssm put-parameter --name "/bedrock-configrules/global/DeployRAG01" --value "false" --overwrite

# Deploy with selective packaging (only FMI-04 and FMI-11 will be packaged)
./scripts/deploy.sh --bucket your-bucket

# Override and package all controls
./scripts/deploy.sh --bucket your-bucket --package-all
```

## 🛠️ Deployment Options

### Option 1: Automated Deployment (Recommended)

The simplest way to deploy the entire solution:

```bash
# Basic deployment (packages only enabled controls)
./scripts/deploy.sh --bucket your-unique-bucket-name

# With specific region and profile
./scripts/deploy.sh --bucket your-bucket --region us-west-2 --profile production

# Update existing deployment
./scripts/deploy.sh --bucket your-bucket --update

# Package all controls regardless of enabled/disabled status
./scripts/deploy.sh --bucket your-bucket --package-all
```

### Option 2: Step-by-Step Deployment

For users who prefer manual control:

```bash
# Step 1: Deploy SSM parameters stack (optional - done automatically)
aws cloudformation deploy \
  --template-file parameters/ssm-parameters.yaml \
  --stack-name bedrock-security-ssm-parameters

# Step 2: Deploy main security controls
./scripts/deploy.sh --bucket your-bucket
```

## 📊 Deployment Process Flow

The deployment script follows this process:

```
1. Prerequisites Validation
   ├── Check AWS CLI installation
   ├── Validate AWS credentials
   ├── Verify required files exist
   └── Check controls directory structure

2. SSM Parameters Stack
   ├── Check if stack exists
   ├── Deploy if missing
   └── Validate deployment

3. S3 Bucket Management
   ├── Check if bucket exists
   ├── Create with regional configuration
   └── Enable versioning

4. Parameter Updates
   ├── Update bucket name in SSM
   └── Validate parameter update

5. Lambda Function Packaging
   ├── Package all control functions
   ├── Upload to S3 bucket
   └── Clean up temporary files

6. CloudFormation Deployment
   ├── Package main template
   ├── Deploy/update stack
   └── Validate deployment

7. Deployment Summary
   ├── Display success/failure status
   ├── Provide console links
   └── Show next steps
```

## 🔧 Configuration Management

### SSM Parameter Structure

All configuration is managed through AWS Systems Manager Parameter Store:

```
/bedrock-configrules/
├── global/
│   ├── TemplatesBucketName          # S3 bucket for templates
│   ├── DeployFMI01                  # Control deployment flags
│   ├── DeployFMI02
│   ├── ...
│   ├── EnableAutoRemediation        # Global settings
│   ├── ConfigRuleFrequency
│   └── NotificationTopicArn
├── fmi-03/
│   ├── RequiredTagKeys              # Control-specific parameters
│   ├── MinTagConditions
│   └── RolePathFilter
├── fmi-01/
│   ├── MaxWildcardActions
│   ├── AllowedWildcardActions
│   └── ProhibitedActions
└── ...
```

### Customizing Configuration

```bash
# Enable specific controls
aws ssm put-parameter \
  --name "/bedrock-configrules/global/DeployFMI04" \
  --value "true" \
  --overwrite

# Configure control-specific settings
aws ssm put-parameter \
  --name "/bedrock-configrules/fmi-03/RequiredTagKeys" \
  --value "Environment,Project,Owner,CostCenter" \
  --overwrite

# Update global settings
aws ssm put-parameter \
  --name "/bedrock-configrules/global/EnableAutoRemediation" \
  --value "true" \
  --overwrite

# Apply changes
./scripts/deploy.sh --bucket your-bucket --update
```

## 🚨 Error Handling and Troubleshooting

### Common Deployment Issues

#### 1. AWS CLI Not Found
```
❌ Error: AWS CLI is not installed or not in PATH
💡 Please install AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
```

**Solution:**
```bash
# Install AWS CLI v2 (Linux/macOS)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version
```

#### 2. Invalid AWS Credentials
```
❌ Error: AWS credentials not configured or invalid
💡 Please configure AWS credentials using: aws configure
```

**Solution:**
```bash
# Configure default credentials
aws configure

# Or configure specific profile
aws configure --profile your-profile

# Verify credentials
aws sts get-caller-identity
```

#### 3. S3 Bucket Creation Failed
```
❌ Error: Failed to create S3 bucket: your-bucket
💡 This could be due to:
   - Bucket name already exists globally
   - Insufficient IAM permissions (s3:CreateBucket)
   - Invalid bucket name format
```

**Solution:**
```bash
# Use a unique bucket name
./scripts/deploy.sh --bucket your-unique-bucket-$(date +%s)

# Or use existing bucket
./scripts/deploy.sh --bucket your-existing-bucket
```

#### 4. SSM Parameter Update Failed
```
❌ Error: Failed to update SSM parameter '/bedrock-configrules/global/TemplatesBucketName'
💡 This could be due to:
   - The SSM parameters stack may not have been deployed properly
   - Insufficient IAM permissions for SSM operations
```

**Solution:**
```bash
# Manually deploy SSM parameters stack
aws cloudformation deploy \
  --template-file parameters/ssm-parameters.yaml \
  --stack-name bedrock-security-ssm-parameters

# Then retry main deployment
./scripts/deploy.sh --bucket your-bucket
```

#### 5. CloudFormation Stack Deployment Failed
```
💥 ❌ Deployment failed. Check the CloudFormation console for details.
🔗 Console: https://region.console.aws.amazon.com/cloudformation/home
```

**Solution:**
1. Check CloudFormation console for detailed error messages
2. Review stack events for specific resource failures
3. Verify IAM permissions for all required services
4. Check parameter values in SSM Parameter Store

### Validation Commands

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name bedrock-security-configrules-pack \
  --query 'Stacks[0].StackStatus'

# Check SSM parameters
aws ssm get-parameters-by-path \
  --path "/bedrock-configrules/" \
  --recursive \
  --query 'Parameters[*].[Name,Value]' \
  --output table

# Verify Config rules
aws configservice describe-config-rules \
  --query 'ConfigRules[?starts_with(ConfigRuleName, `bedscr-`)].{Name:ConfigRuleName,State:ConfigRuleState}' \
  --output table

# Check Lambda functions
aws lambda list-functions \
  --query 'Functions[?starts_with(FunctionName, `bedscr-`)].{Name:FunctionName,Runtime:Runtime,State:State}' \
  --output table
```

## 📈 Post-Deployment

### Immediate Next Steps

1. **Verify Deployment**
   - Check CloudFormation stacks in AWS console
   - Verify Config rules are active
   - Confirm Lambda functions are deployed

2. **Review Configuration**
   - Check SSM parameters match your requirements
   - Update control-specific settings as needed
   - Configure notification topics

3. **Test Compliance**
   - Trigger Config rule evaluations
   - Review compliance results
   - Test remediation functions

### Monitoring and Maintenance

```bash
# Monitor Config rule compliance
aws configservice get-compliance-summary-by-config-rule

# Check Lambda function logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/bedscr-

# Update configuration
aws ssm put-parameter --name "/bedrock-configrules/global/DeployFMI11" --value "true" --overwrite
./scripts/deploy.sh --bucket your-bucket --update
```

## 🔄 Updates and Maintenance

### Updating the Deployment

```bash
# Update with new configuration
./scripts/deploy.sh --bucket your-bucket --update

# Force update all resources
./scripts/deploy.sh --bucket your-bucket --update --force
```

### Adding New Controls

1. Enable the control in SSM parameters
2. Configure control-specific parameters
3. Update the deployment

```bash
# Enable new control
aws ssm put-parameter \
  --name "/bedrock-configrules/global/DeployRAG02" \
  --value "true" \
  --overwrite

# Apply changes
./scripts/deploy.sh --bucket your-bucket --update
```

## 🧹 Cleanup

### Complete Cleanup

```bash
# Delete main stack
aws cloudformation delete-stack --stack-name bedrock-security-configrules-pack

# Delete SSM parameters stack
aws cloudformation delete-stack --stack-name bedrock-security-ssm-parameters

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name bedrock-security-configrules-pack
aws cloudformation wait stack-delete-complete --stack-name bedrock-security-ssm-parameters

# Optional: Remove S3 bucket (be careful!)
aws s3 rb s3://your-bucket --force
```

### Partial Cleanup

```bash
# Disable specific controls
aws ssm put-parameter \
  --name "/bedrock-configrules/global/DeployFMI04" \
  --value "false" \
  --overwrite

# Update deployment to remove disabled controls
./scripts/deploy.sh --bucket your-bucket --update
```

## 📞 Support

If you encounter issues not covered in this guide:

1. Check the [README.md](../README.md) for additional information
2. Review the [troubleshooting section](#error-handling-and-troubleshooting)
3. Check AWS CloudFormation console for detailed error messages
4. Open an issue in the project repository

---

**Ready to deploy?** Start with the [Quick Start](../README.md#-quick-start) section in the main README.