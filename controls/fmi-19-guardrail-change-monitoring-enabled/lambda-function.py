import boto3
import json
import logging
import traceback
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
config = boto3.client('config')
events = boto3.client('events')
sns = boto3.client('sns')
sts = boto3.client('sts')

def handler(event, context):
    """
    AWS Config rule to check if EventBridge rule exists for immediate SNS alerts on guardrail changes.
    Control ID: FMI-19 - bedrock-guardrail-change-monitoring-check
    
    This rule evaluates the account once to ensure simple EventBridge → SNS monitoring exists.
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        logger.error(traceback.format_exc())
        invoking_event = {}
        rule_parameters = {}

    # Get account ID
    account_id = event.get('accountId')
    if not account_id:
        account_id = context.invoked_function_arn.split(':')[4]
    logger.info(f"Account ID: {account_id}")

    # Get result token
    result_token = event.get('resultToken')
    logger.info(f"Result token available: {bool(result_token)}")

    # Get parameters with defaults
    sns_topic_arn = rule_parameters.get('guardrailChangeNotificationTopicArn', '').strip()
    eventbridge_rule_name = rule_parameters.get('eventBridgeRuleName', 'bedrock-guardrail-change-alerts')
    rule_state = rule_parameters.get('eventBridgeRuleState', 'ENABLED')
    
    logger.info(f"Parameters - SNS Topic: {sns_topic_arn}")
    logger.info(f"Parameters - EventBridge Rule: {eventbridge_rule_name}")
    logger.info(f"Parameters - Rule State: {rule_state}")
    
    try:
        # Check simple EventBridge → SNS monitoring
        compliance_result = check_simple_guardrail_monitoring(
            sns_topic_arn,
            eventbridge_rule_name,
            rule_state
        )
        
        compliance_type = compliance_result['compliance_type']
        annotation = compliance_result['annotation']
        
    except Exception as e:
        logger.error(f"Error evaluating guardrail monitoring: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating monitoring: {str(e)[:200]}'  # Truncate for annotation limit
    
    return put_account_level_evaluation(config, result_token, account_id, compliance_type, annotation, invoking_event)

def check_simple_guardrail_monitoring(sns_topic_arn, eventbridge_rule_name, expected_rule_state):
    """
    Check if simple EventBridge → SNS monitoring exists for guardrail changes.
    
    Returns:
        Dict with compliance_type and annotation
    """
    logger.info("Checking simple EventBridge → SNS guardrail monitoring")
    
    try:
        # Step 1: Find EventBridge rule for Bedrock guardrail events
        eventbridge_rule = find_bedrock_guardrail_eventbridge_rule(eventbridge_rule_name)
        if not eventbridge_rule:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': 'No EventBridge rule found for Bedrock guardrail monitoring'
            }
        
        rule_name = eventbridge_rule['Name']
        rule_state = eventbridge_rule.get('State', 'DISABLED')
        logger.info(f"Found EventBridge rule: {rule_name}, State: {rule_state}")
        
        # Step 2: Validate rule is enabled (if expected to be enabled)
        if expected_rule_state == 'ENABLED' and rule_state != 'ENABLED':
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': f'EventBridge rule {rule_name} is disabled'
            }
        
        # Step 3: Validate EventBridge rule has SNS target
        sns_target = validate_eventbridge_sns_target(rule_name, sns_topic_arn)
        if not sns_target['valid']:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation': sns_target['reason']
            }
        
        # Step 4: Validate SNS topic exists and is accessible (if specified)
        if sns_topic_arn:
            if not validate_sns_topic_exists(sns_topic_arn):
                return {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': f'SNS topic {sns_topic_arn} is not accessible'
                }
        
        # All checks passed
        return {
            'compliance_type': 'COMPLIANT',
            'annotation': f'Simple guardrail monitoring exists: {rule_name} → SNS'
        }
        
    except Exception as e:
        logger.error(f"Error checking monitoring infrastructure: {str(e)}")
        return {
            'compliance_type': 'NON_COMPLIANT',
            'annotation': f'Error checking infrastructure: {str(e)[:150]}'
        }

def find_bedrock_guardrail_eventbridge_rule(expected_rule_name=None):
    """
    Find EventBridge rule that monitors Bedrock guardrail API events.
    First try the expected rule name, then search by event pattern.
    """
    try:
        # If we have an expected rule name, check it first
        if expected_rule_name:
            try:
                rule_details = events.describe_rule(Name=expected_rule_name)
                event_pattern = rule_details.get('EventPattern')
                
                if event_pattern and is_bedrock_guardrail_pattern(event_pattern):
                    logger.info(f"Found expected Bedrock guardrail monitoring rule: {expected_rule_name}")
                    return rule_details
                else:
                    logger.warning(f"Rule {expected_rule_name} exists but doesn't monitor guardrail events")
            except events.exceptions.ResourceNotFoundException:
                logger.info(f"Expected rule {expected_rule_name} not found, searching all rules")
        
        # Search all rules for guardrail monitoring pattern
        paginator = events.get_paginator('list_rules')
        
        for page in paginator.paginate():
            for rule in page.get('Rules', []):
                rule_name = rule['Name']
                
                # Skip the expected rule name if we already checked it
                if expected_rule_name and rule_name == expected_rule_name:
                    continue
                
                # Get rule details including event pattern
                try:
                    rule_details = events.describe_rule(Name=rule_name)
                    event_pattern = rule_details.get('EventPattern')
                    
                    if event_pattern and is_bedrock_guardrail_pattern(event_pattern):
                        logger.info(f"Found Bedrock guardrail monitoring rule: {rule_name}")
                        return rule_details
                        
                except Exception as e:
                    logger.warning(f"Could not describe rule {rule_name}: {str(e)}")
                    continue
        
        logger.warning("No EventBridge rule found for Bedrock guardrail monitoring")
        return None
        
    except Exception as e:
        logger.error(f"Error searching for EventBridge rules: {str(e)}")
        return None

def is_bedrock_guardrail_pattern(event_pattern_str):
    """
    Check if event pattern monitors Bedrock guardrail API events.
    """
    try:
        pattern = json.loads(event_pattern_str) if isinstance(event_pattern_str, str) else event_pattern_str
        
        # Check for aws.bedrock source
        source = pattern.get('source', [])
        if not isinstance(source, list):
            source = [source]
        
        if 'aws.bedrock' not in source:
            return False
        
        # Check for CloudTrail detail-type
        detail_type = pattern.get('detail-type', [])
        if not isinstance(detail_type, list):
            detail_type = [detail_type]
        
        if 'AWS API Call via CloudTrail' not in detail_type:
            return False
        
        # Check for Bedrock event source and guardrail API events
        detail = pattern.get('detail', {})
        event_source = detail.get('eventSource', [])
        event_name = detail.get('eventName', [])
        
        if not isinstance(event_source, list):
            event_source = [event_source]
        if not isinstance(event_name, list):
            event_name = [event_name]
        
        if 'bedrock.amazonaws.com' not in event_source:
            return False
        
        # Check for guardrail API events
        guardrail_events = ['CreateGuardrail', 'UpdateGuardrail', 'DeleteGuardrail']
        found_events = [event for event in guardrail_events if event in event_name]
        
        if len(found_events) >= 1:  # At least one guardrail event
            logger.info(f"Found Bedrock guardrail pattern with events: {found_events}")
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error parsing event pattern: {str(e)}")
        return False

def validate_eventbridge_sns_target(rule_name, expected_sns_topic_arn):
    """
    Validate EventBridge rule has SNS target.
    """
    try:
        targets_response = events.list_targets_by_rule(Rule=rule_name)
        targets = targets_response.get('Targets', [])
        
        sns_targets = []
        for target in targets:
            target_arn = target.get('Arn', '')
            # Check if target is SNS
            if ':sns:' in target_arn:
                sns_targets.append(target_arn)
                logger.info(f"Found SNS target: {target_arn}")
        
        if not sns_targets:
            return {'valid': False, 'reason': f'EventBridge rule {rule_name} has no SNS targets'}
        
        # If specific SNS topic is expected, validate it exists
        if expected_sns_topic_arn and expected_sns_topic_arn not in sns_targets:
            return {'valid': False, 'reason': f'Expected SNS topic {expected_sns_topic_arn} not found in targets'}
        
        return {'valid': True, 'reason': f'SNS target configured'}
        
    except Exception as e:
        logger.error(f"Error checking EventBridge targets: {str(e)}")
        return {'valid': False, 'reason': f'Error checking targets: {str(e)}'}

def validate_sns_topic_exists(sns_topic_arn):
    """
    Validate SNS topic exists and is accessible.
    """
    try:
        sns.get_topic_attributes(TopicArn=sns_topic_arn)
        logger.info(f"SNS topic {sns_topic_arn} is accessible")
        return True
        
    except Exception as e:
        logger.warning(f"SNS topic {sns_topic_arn} is not accessible: {str(e)}")
        return False

def put_account_level_evaluation(config, result_token, account_id, compliance_type, annotation, invoking_event):
    """
    Put account-level evaluation results to AWS Config.
    """
    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.utcnow().isoformat()
    
    # Use provided account ID
    
    # Put evaluation for account-level compliance
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': account_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation[:256],  # Ensure annotation is within limit
        'OrderingTimestamp': ordering_timestamp
    }
    
    if result_token:
        try:
            config.put_evaluations(
                Evaluations=[evaluation],
                ResultToken=result_token
            )
            logger.info(f"Successfully submitted account-level evaluation: {compliance_type}")
        except Exception as e:
            logger.error(f"Error submitting evaluation: {str(e)}")
            logger.error(traceback.format_exc())
    
    logger.info(f"Account-level evaluation: {compliance_type} - {annotation}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'resourceId': account_id,
            'resourceType': 'AWS::::Account',
            'complianceType': compliance_type,
            'annotation': annotation
        })
    }