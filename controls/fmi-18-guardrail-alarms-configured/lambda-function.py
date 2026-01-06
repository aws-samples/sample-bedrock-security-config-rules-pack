import boto3
import json
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
config = boto3.client('config')
bedrock = boto3.client('bedrock')
cloudwatch = boto3.client('cloudwatch')
logs = boto3.client('logs')


# Constant metric filter pattern for guardrail interventions
# This pattern works without tracing enabled and captures all guardrail interventions
GUARDRAIL_METRIC_FILTER_PATTERN = '{($.output.outputBodyJson.stopReason = "guardrail_intervened")}'


def evaluate_account_guardrail_monitoring(alarm_threshold):
    """
    Evaluate account-level CloudWatch monitoring for Bedrock guardrail interventions.
    
    This function checks if the account has proper CloudWatch monitoring set up
    for guardrail interventions without relying on tracing data.
    
    Args:
        alarm_threshold: Expected alarm threshold value
    
    Returns:
        Dict with compliance_type and annotation
    """
    logger.info("Evaluating account-level guardrail monitoring")
    
    # Get Bedrock logging configuration
    try:
        logging_config = bedrock.get_model_invocation_logging_configuration()
        if not logging_config:
            return {'compliance_type': 'NON_COMPLIANT', 'annotation': "Model invocation logging configuration not found"}
            
        log_group_name = logging_config.get('loggingConfig', {}).get('cloudWatchConfig', {}).get('logGroupName')
    except Exception as e:
        logger.error(f"Error getting Bedrock logging configuration: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f"Model invocation logging is not configured: {str(e)}"}
    
    if not log_group_name:
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': "CloudWatch logging is not configured for Bedrock model invocation logging"}
    
    # Check if any guardrails exist in the account
    try:
        guardrails_response = bedrock.list_guardrails()
        guardrails = guardrails_response.get('guardrails', [])
        
        if not guardrails:
            return {'compliance_type': 'NOT_APPLICABLE', 'annotation': "No guardrails found in account"}
            
        logger.info(f"Found {len(guardrails)} guardrails in account")
            
    except Exception as e:
        logger.error(f"Error listing guardrails: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f"Error listing guardrails: {str(e)}"}
    
    # Get metric filters and alarms
    logger.info(f"Retrieving metric filters for log group: {log_group_name}")
    try:
        metric_filters_response = logs.describe_metric_filters(logGroupName=log_group_name)
        metric_filters = metric_filters_response.get('metricFilters', []) if metric_filters_response else []
        logger.info(f"Found metric filters: {[f.get('filterName') for f in metric_filters]}")
        
        alarms_response = cloudwatch.describe_alarms()
        all_alarms = alarms_response.get('MetricAlarms', []) if alarms_response else []
        logger.info(f"Found CloudWatch alarms: {[a.get('AlarmName') for a in all_alarms]}")
        
    except Exception as e:
        logger.error(f"Error retrieving CloudWatch resources: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f"Error retrieving CloudWatch resources: {str(e)}"}
    
    # Analyze guardrail monitoring
    logger.info("Analyzing account-level guardrail monitoring")
    try:
        return analyze_account_guardrail_monitoring(metric_filters, all_alarms, alarm_threshold)
    except Exception as e:
        logger.error(f"Error analyzing account guardrail monitoring: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f"Error analyzing guardrail monitoring: {str(e)}"}


def analyze_account_guardrail_monitoring(metric_filters, all_alarms, alarm_threshold):
    """
    Analyze metric filters and alarms for account-level guardrail monitoring compliance.
    
    This function checks if the account has proper CloudWatch monitoring set up
    for guardrail interventions using the basic guardrail intervention pattern.
    
    Args:
        metric_filters: List of existing CloudWatch metric filters
        all_alarms: List of existing CloudWatch alarms
        alarm_threshold: Expected alarm threshold value
    
    Returns:
        Dict with compliance_type and annotation
    """
    logger.info("Checking account-level compliance for guardrail monitoring")
    
    # Find matching metric filters for guardrail interventions
    matching_filters = []
    for metric_filter in metric_filters:
        if not isinstance(metric_filter, dict):
            continue
            
        filter_name = metric_filter.get('filterName', '')
        filter_pattern = metric_filter.get('filterPattern', '')
        
        # Check if this filter matches our guardrail intervention pattern
        if filter_pattern and 'stopReason="guardrail_intervened"' in filter_pattern.replace(' ', '').replace('\n', '').replace('\t', ''):
            logger.info(f"Found matching metric filter: {filter_name}")
            matching_filters.append(metric_filter)
    
    # Check for alarms associated with matching filters
    matching_alarms = []
    for metric_filter in matching_filters:
        metric_transformations = metric_filter.get('metricTransformations', [])
        for transformation in metric_transformations:
            if not isinstance(transformation, dict):
                continue
                
            metric_name = transformation.get('metricName')
            metric_namespace = transformation.get('metricNamespace')
            
            if not metric_name or not metric_namespace:
                continue
            
            # Find alarms for this metric
            filter_alarms = [
                alarm for alarm in all_alarms 
                if isinstance(alarm, dict) and 
                   alarm.get('MetricName') == metric_name and 
                   alarm.get('Namespace') == metric_namespace
            ]
            
            # Validate alarm configuration
            valid_alarms = []
            for alarm in filter_alarms:
                if not isinstance(alarm, dict):
                    continue
                    
                # Check threshold and alarm actions
                if (alarm.get('Threshold', 0) == alarm_threshold and 
                    alarm.get('AlarmActions', [])):
                    valid_alarms.append(alarm)
                    logger.info(f"Alarm {alarm.get('AlarmName')} is properly configured")
                else:
                    logger.warning(f"Alarm {alarm.get('AlarmName', 'Unknown')} has incorrect configuration")
            
            if valid_alarms:
                alarm_names = [alarm.get('AlarmName') for alarm in valid_alarms]
                logger.info(f"Found properly configured alarms for metric {metric_name}: {alarm_names}")
            matching_alarms.extend(valid_alarms)
    
    # Evaluate compliance
    filters_found = len(matching_filters)
    alarms_found = len(matching_alarms)
    
    logger.info(f"Compliance check results: {filters_found} metric filters, {alarms_found} alarms found")
    
    if filters_found > 0 and alarms_found > 0:
        return {
            'compliance_type': 'COMPLIANT', 
            'annotation': f'Found {filters_found} metric filter(s) and {alarms_found} alarm(s) for guardrail intervention monitoring'
        }
    elif filters_found > 0 and alarms_found == 0:
        return {
            'compliance_type': 'NON_COMPLIANT', 
            'annotation': f'Found {filters_found} metric filter(s) but no properly configured alarms'
        }
    elif filters_found == 0 and alarms_found > 0:
        return {
            'compliance_type': 'NON_COMPLIANT', 
            'annotation': f'Found {alarms_found} alarm(s) but no metric filters for guardrail interventions'
        }
    else:
        return {
            'compliance_type': 'NON_COMPLIANT', 
            'annotation': f'No metric filters or alarms found for guardrail intervention monitoring'
        }

def handler(event, context):
    """
    AWS Config rule handler for FMI-18: CloudWatch alarms for Bedrock guardrail triggers.
    
    Checks for CloudWatch metric filters and alarms that monitor guardrail interventions
    using the pattern: {($.output.outputBodyJson.stopReason = "guardrail_intervened")}
    
    This simplified approach works without Bedrock tracing enabled and evaluates
    at the account level for comprehensive monitoring compliance.
    
    Args:
        event: AWS Config rule event containing rule parameters and invocation details
        context: AWS Lambda context object
    
    Returns:
        Dict with statusCode and compliance evaluation results
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    try:
        # Parse the Config event
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        message_type = invoking_event.get('messageType', '')
        
        # Get common parameters
        account_id = event.get('accountId') or context.invoked_function_arn.split(':')[4]
        result_token = event.get('resultToken')
        
        # Parse rule parameters for threshold
        rule_parameters = event.get('ruleParameters', '{}')
        if isinstance(rule_parameters, str):
            rule_parameters = json.loads(rule_parameters) if rule_parameters else {}
        
        # Get alarm threshold parameter
        alarm_threshold = float(rule_parameters.get('alarmThreshold', '1.0'))
        
        logger.info(f"Message type: {message_type}")
        logger.info(f"Alarm threshold: {alarm_threshold}")

        # Account-level evaluation for scheduled notifications
        if message_type == 'ScheduledNotification':
            logger.info("Performing account-level evaluation")
            
            # Evaluate account-level guardrail monitoring
            compliance_result = evaluate_account_guardrail_monitoring(alarm_threshold)
            
            logger.info(f"Evaluation result: {compliance_result['compliance_type']}")
            
            return create_account_evaluation(result_token, account_id, 
                                           compliance_result['compliance_type'], 
                                           compliance_result['annotation'])
        else:
            logger.warning(f"Unsupported message type: {message_type}")
            return create_account_evaluation(result_token, account_id, 
                                           'NOT_APPLICABLE', 
                                           f'Unsupported message type: {message_type}')
        
    except Exception as e:
        logger.error(f"Error evaluating Bedrock guardrail CloudWatch alarms: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Try to get account_id safely
        try:
            account_id = event.get('accountId') or context.invoked_function_arn.split(':')[4]
        except (AttributeError, IndexError):
            account_id = 'unknown'
            
        return create_account_evaluation(event.get('resultToken'), account_id, 'NON_COMPLIANT',
                                       f'Error evaluating Bedrock guardrail CloudWatch alarms: {str(e)}')


def create_account_evaluation(result_token, account_id, compliance_type, annotation):
    """
    Create and submit AWS Config evaluation result for account-level evaluation.
    
    Args:
        result_token: AWS Config result token for submitting evaluation
        account_id: AWS account ID being evaluated
        compliance_type: Compliance status (COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE)
        annotation: Human-readable explanation of the compliance result
    
    Returns:
        Dict with statusCode and body containing compliance information
    """
    logger.info(f"Creating account-level evaluation for account {account_id}")
    
    # Use current timestamp for account-level evaluations
    ordering_timestamp = datetime.utcnow().isoformat()
    
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': account_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': ordering_timestamp
    }
    
    if result_token:
        config.put_evaluations(Evaluations=[evaluation], ResultToken=result_token)
    
    return {
        'statusCode': 200,
        'body': json.dumps({'complianceType': compliance_type, 'annotation': annotation})
    }
