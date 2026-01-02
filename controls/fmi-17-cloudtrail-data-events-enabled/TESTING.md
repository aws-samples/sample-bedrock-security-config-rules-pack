# FMI-17: CloudTrail Data Events for Bedrock Resources - Testing Guide

## Overview
FMI-17 (CloudTrail Data Events for Bedrock Resources) validates that CloudTrail data events are properly configured to monitor specified AWS resource types. This control ensures comprehensive audit coverage for AI/ML workloads by checking that all required resource types have CloudTrail data events enabled.

This document helps you understand how the FMI-17 control evaluates CloudTrail configuration for data events compliance.

## Prerequisites
- AWS CLI configured with appropriate permissions
- CloudTrail permissions to modify trails and event selectors
- **Existing CloudTrail trail** that matches the SSM parameter configuration
- AWS Config enabled and the FMI-17 control deployed
- Understanding of CloudTrail advanced event selectors

⚠️ **Note**: The FMI-17 remediation function only modifies existing CloudTrail trails. It does not create S3 buckets or new CloudTrail trails. Ensure you have an existing, active CloudTrail trail before testing remediation.

## Test Setup

### 1. Create Test S3 Bucket for CloudTrail (if needed)
```bash
# Create S3 bucket for CloudTrail logs (only if you don't have an existing trail)
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET_NAME="test-cloudtrail-logs-${ACCOUNT_ID}"
TRAIL_NAME="test-bedrock-trail-${ACCOUNT_ID}"

aws s3 mb s3://${BUCKET_NAME}

# Set bucket policy for CloudTrail
aws s3api put-bucket-policy --bucket ${BUCKET_NAME} --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::'"${BUCKET_NAME}"'",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:'"${ACCOUNT_ID}"':trail/'"${TRAIL_NAME}"'"
        }
      }
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::'"${BUCKET_NAME}"'/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:'"${ACCOUNT_ID}"':trail/'"${TRAIL_NAME}"'"
        }
      }
    }
  ]
}'
```

### 2. Create Test CloudTrail (Non-Compliant)
```bash
# Create a test CloudTrail (without data events - non-compliant)


aws cloudtrail create-trail \
  --name ${TRAIL_NAME} \
  --s3-bucket-name ${BUCKET_NAME} \
  --is-multi-region-trail \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name ${TRAIL_NAME}

# Verify trail is created and logging
aws cloudtrail get-trail-status --name ${TRAIL_NAME}
```

### 3. Configure Test CloudTrail (Partially Compliant)
```bash
# Configure the existing trail with only some required resource types (partially compliant)
aws cloudtrail put-event-selectors \
  --trail-name ${TRAIL_NAME} \
  --advanced-event-selectors '[
    {
      "Name": "DataEvents-Bedrock-Model",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::Model"]
        }
      ]
    }
  ]'

# Verify configuration
aws cloudtrail get-event-selectors --trail-name ${TRAIL_NAME}
```

### 4. Configure Test CloudTrail (Compliant)
```bash
# Configure the existing trail with all required resource types (compliant)
aws cloudtrail put-event-selectors \
  --trail-name ${TRAIL_NAME} \
  --advanced-event-selectors '[
    {
      "Name": "DataEvents-Bedrock-Model",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::Model"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-AsyncInvoke",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::AsyncInvoke"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-Guardrail",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::Guardrail"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-AgentAlias",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::AgentAlias"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-FlowAlias",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::FlowAlias"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-InlineAgent",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::InlineAgent"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-KnowledgeBase",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::KnowledgeBase"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-PromptVersion",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::PromptVersion"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-Session",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::Session"]
        }
      ]
    },
    {
      "Name": "DataEvents-Bedrock-FlowExecution",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Data"]
        },
        {
          "Field": "resources.type",
          "Equals": ["AWS::Bedrock::FlowExecution"]
        }
      ]
    }
  ]'

# Start logging
aws cloudtrail start-logging --name test-trail-compliant
```

## Understanding Control Evaluation

### 1. Trigger Config Rule Evaluation
After creating test CloudTrail configurations, trigger the Config rule to evaluate them:

```bash
# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-17-cloudtrail-data-events
```

### 2. Check Evaluation Results
View the compliance status of your account:

```bash
# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-17-cloudtrail-data-events
```

### 3. Expected Results

**No CloudTrail (if you delete all trails):**
- **Status:** NON_COMPLIANT
- **Reason:** No CloudTrail trails found

**Non-Compliant Trail (no data events configured):**
- **Status:** NON_COMPLIANT
- **Reason:** CloudTrail data events missing for 10 of 10 required resource types

**Partially Compliant Trail (some data events configured):**
- **Status:** NON_COMPLIANT
- **Reason:** CloudTrail data events missing for 9 of 10 required resource types

**Compliant Trail (all data events configured):**
- **Status:** COMPLIANT
- **Reason:** CloudTrail data events are enabled for all 10 required resource types

## Testing Automatic Remediation

### 1. Update Remediation Configuration (Manual Step)
**Before triggering remediation, update the CloudTrail parameters in the AWS Console:**

1. Go to **AWS Config Console** → **Rules** → `fmi-17-cloudtrail-data-events`
2. Click **Remediation Action** → **Edit**
3. Under **Parameters**, update the **TrailName** value to the actual trail name (use `echo $TRAIL_NAME` to see the value)
4. Click **Save**

Important: The remediation function does NOT create S3 buckets or CloudTrail trails. It only updates existing, active trails with the required data event selectors. Ensure the trail specified in the remediation parameter 'dev-bedrock-data-trail' exists before running remediation or replace 'dev-bedrock-data-trail' with your trail name.

### 2. Trigger Automatic Remediation
```bash
# Get account ID for account-level remediation
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Trigger remediation for the non-compliant account
aws configservice start-remediation-execution \
  --config-rule-name fmi-17-cloudtrail-data-events \
  --resource-keys resourceType=AWS::::Account,resourceId=$ACCOUNT_ID
```

### 3. Check Remediation Status
Monitor the remediation execution:

```bash
# Check remediation execution status
aws configservice describe-remediation-execution-status \
  --config-rule-name fmi-17-cloudtrail-data-events
```

### 4. Verify Remediation Results
Check if CloudTrail data events were configured:

```bash
# Check event selectors on the specified trail
aws cloudtrail get-event-selectors --trail-name $TRAIL_NAME

# Verify trail is still logging
aws cloudtrail get-trail-status --name $TRAIL_NAME

# Verify all required resource types have data events configured
aws cloudtrail get-event-selectors --trail-name $TRAIL_NAME \
  --query 'AdvancedEventSelectors[?contains(FieldSelectors[?Field==`eventCategory`].Equals[], `Data`)]'
```

### 5. Re-evaluate After Remediation
Trigger another evaluation to confirm compliance:

```bash
# Re-trigger evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names fmi-17-cloudtrail-data-events

# Check evaluation results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name fmi-17-cloudtrail-data-events
```

### 6. Expected Results (After Automatic Remediation)

**CloudTrail with Bedrock Data Events:**
- **Status:** COMPLIANT
- **Reason:** CloudTrail trail configured with advanced event selectors for all required Bedrock resource types

**Important:** Remediation updates the existing CloudTrail trail and does not create new trails or S3 buckets.

## Data Events Testing
To verify that data events are actually being captured:

```bash
# Perform some Bedrock operations (if you have Bedrock resources)
aws bedrock list-foundation-models

# Wait a few minutes, then check CloudTrail logs in S3
aws s3 ls s3://${BUCKET_NAME}/ --recursive

# Download and examine recent log files to verify data events are captured
```

## Cleanup Test Resources
```bash
# Reset the trail to remove data events (if you want to clean up)
aws cloudtrail put-event-selectors \
  --trail-name $TRAIL_NAME \
  --advanced-event-selectors '[
    {
      "Name": "Management events only",
      "FieldSelectors": [
        {
          "Field": "eventCategory",
          "Equals": ["Management"]
        }
      ]
    }
  ]'

# Optionally delete the test trail (only if you created it for testing)
aws cloudtrail stop-logging --name ${TRAIL_NAME} 2>/dev/null || true
aws cloudtrail delete-trail --name ${TRAIL_NAME} 2>/dev/null || true

# Delete test S3 bucket (only if you created it for testing)
aws s3 rm s3://${BUCKET_NAME} --recursive 2>/dev/null || true
aws s3 rb s3://${BUCKET_NAME} 2>/dev/null || true

# Note: Be careful not to delete production CloudTrail trails or S3 buckets
```

## Viewing Results
Check results in AWS Config Console → Rules → `fmi-17-cloudtrail-data-events`


This comprehensive testing approach ensures that FMI-17 correctly evaluates CloudTrail data events configuration and that remediation works as expected.