# FMI-06: Model Logs KMS Encryption

## Description
Ensures customer-managed KMS keys are used for encryption of Bedrock model invocation logs stored in CloudWatch Logs and S3. This control validates that sensitive model invocation data is properly encrypted at rest using customer-controlled encryption keys.

**Config Resource Type:** `AWS::Logs::LogGroup`, `AWS::S3::Bucket`

## Prerequisites
- Model invocation logging must be enabled (see FMI-04)
- Customer-managed KMS keys must be available
- KMS key should have additional policy statements allowing Bedrock services to use the key (replace `<BUCKET-NAME>` and `<LOG-GROUP-NAME>` with your specific values):

```json
{
  "Sid": "EnableBedrockModelLogsEncryption",
  "Effect": "Allow",
  "Principal": {
    "Service": [
      "bedrock.amazonaws.com",
      "logs.amazonaws.com",
      "s3.amazonaws.com"
    ]
  },
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "ArnEquals": {
      "kms:EncryptionContext:aws:logs:arn": "arn:aws:logs:*:${AWS::AccountId}:log-group:<LOG-GROUP-NAME>"
    }
  }
},
{
  "Sid": "EnableS3BedrockLogsEncryption", 
  "Effect": "Allow",
  "Principal": {
    "Service": "s3.amazonaws.com"
  },
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "s3.${AWS::Region}.amazonaws.com"
    },
    "StringLike": {
      "kms:EncryptionContext:aws:s3:arn": [
        "arn:aws:s3:::<BUCKET-NAME>/*",
        "arn:aws:s3:::<BUCKET-NAME>"
      ]
    }
  }
}
```

These statements should be added to your existing KMS key policy alongside the standard root user access statement. Replace `<BUCKET-NAME>` with your specific S3 bucket name and `<LOG-GROUP-NAME>` with your specific CloudWatch log group name used for Bedrock model invocation logging.
- Appropriate IAM permissions for KMS key usage

## Related Controls
- **FMI-04:** Model Invocation Logging - Must be enabled for this control to apply
- **FMI-07:** Knowledge Bases KMS - Similar encryption requirements for knowledge bases
- **FMI-08:** Guardrails KMS - Similar encryption requirements for guardrails

## Usage Patterns
- FMI (Foundation Model Invocation)
- RAG (Retrieval-Augmented Generation) 
- Agentic AI workflows
- Model Customization

## Parameters

### Check Function Parameters
Parameters used by the evaluation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `RequiredKmsKeyIds` | String | Comma-separated list of allowed KMS key IDs/ARNs for encryption | `null` - (accepts any customer-managed key) | Optional |

### Remediation Function Parameters
Configuration parameters used by the remediation Lambda function:

| Parameter | Type | Description | Default | Required |
|-----------|------|-------------|---------|----------|
| `KmsKeyId` | String | KMS key ID to use for encryption | `null` | Required |
| `ExistingLoggingRoleArn` | String | ARN of existing IAM role for Bedrock logging (optional) | `null` | Optional |

**Important:** Parameter values shown in the AWS Config console are **sample/example values only**. You must:
- **Provide a valid KMS key ID** that exists in your account
- **Ensure the KMS key policy** allows Bedrock service access
- **Update the SSM parameter** `/bedrock-configrules/fmi-06/KmsKeyId` with your key ID before running remediation

### Required KMS Key Policy
The KMS key used for remediation must have a policy that includes the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<Account_Id>:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudWatch Logs",
      "Effect": "Allow",
      "Principal": {
        "Service": "logs.us-east-1.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow Bedrock Service",
      "Effect": "Allow",
      "Principal": {
        "Service": "bedrock.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow S3 Service",
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Allow All AWS Services (Testing Only)",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<Account_Id>:root"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": [
            "logs.us-east-1.amazonaws.com",
            "s3.us-east-1.amazonaws.com",
            "bedrock.us-east-1.amazonaws.com"
          ]
        }
      }
    },
    {
      "Sid": "AllowS3VectorsServicePrincipal",
      "Effect": "Allow",
      "Principal": {
        "Service": "indexing.s3vectors.amazonaws.com"
      },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "<Account_Id>"
        },
        "ForAnyValue:StringEquals": {
          "kms:EncryptionContextKeys": [
            "aws:s3vectors:arn",
            "aws:s3vectors:resource-id"
          ]
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:s3vectors:us-east-1:<Account_Id>:bucket/*"
        }
      }
    },
    {
      "Sid": "allow lambda",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<Account_Id>:role/BedrockGuardrailsKmsCheckFunctionRole"
      },
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**Note:** Replace `<Account_Id>` with your actual AWS account ID.


## Compliance

### Compliant Conditions
A resource is considered **COMPLIANT** when:
- Model invocation logging is enabled in Bedrock (has `loggingConfig`)
- At least one logging destination uses KMS encryption:
  - **S3 logging**: Bucket uses `aws:kms` encryption with customer-managed key
  - **CloudWatch logging**: Log group has `kmsKeyId` configured
- If `requiredKmsKeyIds` parameter is specified, only those KMS keys are accepted
- KMS key ID matches the approved list (if specified)

### Non-Compliant Conditions
A resource is considered **NON_COMPLIANT** when:
- Model invocation logging is not enabled (no `loggingConfig`)
- S3 bucket does not use KMS encryption (`SSEAlgorithm` is not `aws:kms`)
- CloudWatch log group does not have `kmsKeyId` configured
- KMS key ID is not in the `requiredKmsKeyIds` list (if specified)
- Error occurs while checking encryption configuration

### Not Applicable Conditions
This control does not have NOT_APPLICABLE conditions. All AWS accounts are evaluated for Bedrock model logs KMS encryption.

**Note:** The specific requirements checked by this control are defined in the control's Lambda function implementation. Refer to the actual control code for precise compliance criteria.

## Remediation Behavior
When remediation is triggered, the function will:
1. **Identify log groups and S3 buckets** used for Bedrock logging
2. **Create KMS key** if none is specified and creation is enabled
3. **Configure CloudWatch log group encryption** with customer-managed key
4. **Configure S3 bucket encryption** with customer-managed key
5. **Enable key rotation** if configured
6. **Update key policies** to allow Bedrock service access


