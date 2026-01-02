import boto3
import json
import logging
import traceback
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
events = boto3.client('events')
sns = boto3.client('sns')
sts = boto3.client('sts')

def handler(event, context):
    """
    AWS Lambda function to remediate non-compliant Bedrock guardrail change monitoring.
    This function creates simple monitoring infrastructure: EventBridge Rule → SNS Topic.
    """
    logger.info("Starting remediation for Bedrock guardrail change monitoring")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    try:
        
        # Parse parameters from SSM payload
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        logger.info(f"Rule parameters: {rule_parameters}")
        
        # Extract account ID (resource ID for account-level rules)
        account_id = rule_parameters.get('resourceId')
        if not account_id:
            raise ValueError("Missing resourceId parameter")
        
        logger.info(f"Processing account-level remediation for account: {account_id}")
        
        # Get configuration parameters with defaults
        sns_topic_arn = rule_parameters.get('guardrailChangeNotificationTopicArn', '').strip()
        eventbridge_rule_name = rule_parameters.get('eventBridgeRuleName', 'bedrock-guardrail-change-alerts')
        rule_state = rule_parameters.get('eventBridgeRuleState', 'ENABLED')
        kms_key_id = rule_parameters.get('kmsKeyId', '').strip()
        
        logger.info(f"Configuration - Rule: {eventbridge_rule_name}")
        logger.info(f"Configuration - SNS Topic: {sns_topic_arn}")
        logger.info(f"Configuration - Rule State: {rule_state}")
        
        # Track remediation results
        created_resources = []
        warnings = []
        errors = []
        
        # Step 1: Create or validate SNS topic
        if not sns_topic_arn:
            sns_result = create_sns_topic(kms_key_id)
            if sns_result['success']:
                sns_topic_arn = sns_result['topic_arn']
                created_resources.append(f"SNS topic: {sns_topic_arn}")
            else:
                errors.append(f"SNS topic creation failed: {sns_result['error']}")
                sns_topic_arn = None
        else:
            # Validate existing SNS topic
            if validate_sns_topic(sns_topic_arn):
                logger.info(f"Using existing SNS topic: {sns_topic_arn}")
            else:
                warnings.append(f"SNS topic {sns_topic_arn} may not be accessible")
        
        # Step 2: Create EventBridge rule
        if sns_topic_arn:
            eventbridge_result = create_eventbridge_rule(eventbridge_rule_name, rule_state)
            if eventbridge_result['success']:
                created_resources.append(f"EventBridge rule: {eventbridge_rule_name}")
            else:
                errors.append(f"EventBridge rule failed: {eventbridge_result['error']}")
        
        # Step 3: Add SNS target to EventBridge rule
        if sns_topic_arn and eventbridge_result.get('success'):
            sns_target_result = add_sns_target_to_rule(eventbridge_rule_name, sns_topic_arn)
            if sns_target_result['success']:
                created_resources.append(f"SNS target for rule: {eventbridge_rule_name}")
            else:
                errors.append(f"SNS target failed: {sns_target_result['error']}")
        
        # Step 4: Set SNS topic permissions
        if sns_topic_arn and eventbridge_result.get('success'):
            permission_result = set_sns_topic_permissions(sns_topic_arn)
            if permission_result['success']:
                created_resources.append(f"SNS permissions for EventBridge")
            else:
                warnings.append(f"SNS permissions warning: {permission_result['error']}")
        
        # Determine overall status
        total_steps = 3  # SNS topic, EventBridge rule, SNS target
        successful_steps = len([r for r in created_resources if not r.startswith("SNS permissions")])
        failed_steps = len(errors)
        
        if failed_steps == 0 and successful_steps >= 2:  # At least rule and target
            status_code = 200
            message = 'Simple guardrail monitoring remediation completed successfully'
        elif successful_steps > 0:
            status_code = 207  # Partial success
            message = f'Remediation partially completed. {successful_steps} of {total_steps} steps successful'
        else:
            status_code = 500
            message = 'Remediation failed - no resources were created'
        
        # Return standardized results
        result = {
            'statusCode': status_code,
            'body': {
                'message': message,
                'accountId': account_id,
                'monitoringScope': 'account-level',
                'createdResources': created_resources,
                'warnings': warnings,
                'errors': errors,
                'summary': {
                    'totalSteps': total_steps,
                    'successfulSteps': successful_steps,
                    'failedSteps': failed_steps
                },
                'configuration': {
                    'eventBridgeRuleName': eventbridge_rule_name,
                    'snsTopicArn': sns_topic_arn,
                    'ruleState': rule_state
                }
            }
        }
        
        logger.info(f"Remediation completed. Status: {status_code}")
        return result
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Simple guardrail monitoring remediation failed',
                'accountId': rule_parameters.get('resourceId', 'unknown') if 'rule_parameters' in locals() else 'unknown'
            }
        }

def create_sns_topic(kms_key_id):
    """
    Create SNS topic for guardrail change notifications.
    """
    try:
        topic_name = "bedrock-guardrail-change-alerts"
        
        # Create SNS topic
        create_params = {
            'Name': topic_name,
            'Attributes': {
                'DisplayName': 'Bedrock Guardrail Change Alerts'
            }
        }
        
        # Add KMS encryption if specified
        if kms_key_id:
            create_params['Attributes']['KmsMasterKeyId'] = kms_key_id
            logger.info(f"Creating SNS topic with KMS encryption: {kms_key_id}")
        
        response = sns.create_topic(**create_params)
        topic_arn = response['TopicArn']
        
        logger.info(f"Created SNS topic: {topic_arn}")
        return {'success': True, 'topic_arn': topic_arn}
        
    except Exception as e:
        logger.error(f"Error creating SNS topic: {str(e)}")
        return {'success': False, 'error': str(e)}

def validate_sns_topic(topic_arn):
    """
    Validate that SNS topic exists and is accessible.
    """
    try:
        sns.get_topic_attributes(TopicArn=topic_arn)
        return True
    except Exception as e:
        logger.warning(f"SNS topic validation failed: {str(e)}")
        return False

def create_eventbridge_rule(rule_name, rule_state):
    """
    Create EventBridge rule for monitoring Bedrock guardrail API events.
    """
    try:
        # Event pattern for Bedrock guardrail API calls
        event_pattern = {
            "source": ["aws.bedrock"],
            "detail-type": ["AWS API Call via CloudTrail"],
            "detail": {
                "eventSource": ["bedrock.amazonaws.com"],
                "eventName": ["CreateGuardrail", "UpdateGuardrail", "DeleteGuardrail"]
            }
        }
        
        # Check if rule already exists
        try:
            existing_rule = events.describe_rule(Name=rule_name)
            logger.info(f"EventBridge rule {rule_name} already exists, updating if needed")
        except events.exceptions.ResourceNotFoundException:
            logger.info(f"Creating new EventBridge rule: {rule_name}")
        
        # Create or update EventBridge rule
        events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State=rule_state,
            Description="Direct SNS alerts for Bedrock guardrail configuration changes"
        )
        
        logger.info(f"EventBridge rule {rule_name} created/updated successfully")
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Error creating EventBridge rule {rule_name}: {str(e)}")
        return {'success': False, 'error': str(e)}

def add_sns_target_to_rule(rule_name, sns_topic_arn):
    """
    Add SNS topic as target to EventBridge rule.
    """
    try:
        target_id = "guardrail-sns-target"
        
        # Check if target already exists
        try:
            existing_targets = events.list_targets_by_rule(Rule=rule_name)
            existing_target_arns = [target.get('Arn') for target in existing_targets.get('Targets', [])]
            
            if sns_topic_arn in existing_target_arns:
                logger.info(f"SNS target {sns_topic_arn} already exists for rule {rule_name}")
                return {'success': True}
        except Exception as e:
            logger.warning(f"Could not check existing targets: {str(e)}")
        
        # Add SNS target
        events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': sns_topic_arn
                }
            ]
        )
        
        logger.info(f"Added SNS target to rule {rule_name}")
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Error adding SNS target to rule {rule_name}: {str(e)}")
        return {'success': False, 'error': str(e)}

def set_sns_topic_permissions(sns_topic_arn):
    """
    Set SNS topic permissions to allow EventBridge to publish.
    """
    try:
        account_id = sts.get_caller_identity()['Account']
        
        # Policy to allow EventBridge to publish
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "events.amazonaws.com"
                    },
                    "Action": "sns:Publish",
                    "Resource": sns_topic_arn,
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id
                        }
                    }
                }
            ]
        }
        
        # Set topic policy
        sns.set_topic_attributes(
            TopicArn=sns_topic_arn,
            AttributeName='Policy',
            AttributeValue=json.dumps(policy)
        )
        
        logger.info(f"Set SNS topic permissions for EventBridge")
        return {'success': True}
        
    except Exception as e:
        logger.error(f"Error setting SNS topic permissions: {str(e)}")
        return {'success': False, 'error': str(e)}