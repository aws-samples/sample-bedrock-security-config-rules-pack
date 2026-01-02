import boto3
import json
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
bedrock = boto3.client('bedrock')
logs = boto3.client('logs')
cloudwatch = boto3.client('cloudwatch')
sns = boto3.client('sns')

# Metric filter pattern for ALL guardrail interventions
GUARDRAIL_METRIC_FILTER_PATTERN = '{($.output.outputBodyJson.stopReason = "guardrail_intervened")}'

def create_account_metric_filter(log_group_name, metric_namespace):
    """Create single account-level CloudWatch metric filter for all guardrail interventions."""
    filter_name = "bedrock-guardrail-interventions-filter"
    metric_name = "guardrail-interventions"
    
    try:
        # Check if filter already exists
        existing_filters = logs.describe_metric_filters(
            logGroupName=log_group_name,
            filterNamePrefix=filter_name
        ).get('metricFilters', [])
        
        if existing_filters:
            logger.info(f"Account-level metric filter '{filter_name}' already exists")
            return True, filter_name, metric_name
        
        # Create the metric filter
        logs.put_metric_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern=GUARDRAIL_METRIC_FILTER_PATTERN,
            metricTransformations=[{
                'metricName': metric_name,
                'metricNamespace': metric_namespace,
                'metricValue': '1',
                'unit': 'Count'
            }]
        )
        
        logger.info(f"Account-level metric filter '{filter_name}' created successfully")
        return True, filter_name, metric_name
        
    except Exception as e:
        logger.error(f"Error creating metric filter '{filter_name}': {str(e)}")
        return False, filter_name, metric_name

def create_account_alarm(metric_name, metric_namespace, alarm_name_prefix, alarm_threshold, sns_topic_arn):
    """Create single account-level CloudWatch alarm for all guardrail interventions."""
    alarm_name = f"{alarm_name_prefix}-interventions-alarm"
    
    try:
        # Check if alarm already exists
        existing_alarms = cloudwatch.describe_alarms(AlarmNames=[alarm_name]).get('MetricAlarms', [])
        if existing_alarms:
            logger.info(f"Account-level alarm '{alarm_name}' already exists")
            return True, alarm_name
        
        # Prepare alarm actions
        alarm_actions = []
        if sns_topic_arn and sns_topic_arn.strip():
            try:
                sns.get_topic_attributes(TopicArn=sns_topic_arn)
                alarm_actions.append(sns_topic_arn)
            except Exception as e:
                logger.warning(f"Could not configure SNS action: {str(e)}")
        
        # Create the alarm
        cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='GreaterThanOrEqualToThreshold',
            EvaluationPeriods=1,
            MetricName=metric_name,
            Namespace=metric_namespace,
            Period=300,
            Statistic='Sum',
            Threshold=float(alarm_threshold),
            ActionsEnabled=True,
            AlarmActions=alarm_actions,
            AlarmDescription=f"Account-level Bedrock guardrail interventions alarm (threshold: {alarm_threshold})",
            Unit='Count',
            TreatMissingData='notBreaching'
        )
        
        logger.info(f"Account-level alarm '{alarm_name}' created successfully")
        return True, alarm_name
        
    except Exception as e:
        logger.error(f"Error creating alarm '{alarm_name}': {str(e)}")
        return False, alarm_name

def handler(event, context):
    """AWS Lambda handler for FMI-18 account-level Bedrock guardrail CloudWatch alarms remediation."""
    try:
        logger.info("Starting account-level Bedrock guardrail CloudWatch alarms remediation")
        
        # Parse parameters
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        alarm_name_prefix = rule_parameters.get('alarmNamePrefix', 'bedrock-guardrail')
        metric_namespace = rule_parameters.get('metricNamespace', 'Bedrock/Guardrails')
        sns_topic_arn = rule_parameters.get('snsTopicArn', '').strip()
        
        # Parse alarm threshold
        try:
            alarm_threshold = max(1.0, float(rule_parameters.get('alarmThreshold', '1.0')))
        except (ValueError, TypeError):
            alarm_threshold = 1.0
        
        # Get Bedrock logging configuration
        try:
            logging_config = bedrock.get_model_invocation_logging_configuration()
            log_group_name = logging_config.get('loggingConfig', {}).get('cloudWatchConfig', {}).get('logGroupName')
        except Exception as e:
            return {
                'statusCode': 500,
                'body': {'error': str(e), 'message': 'Model invocation logging is not configured'}
            }
        
        if not log_group_name:
            return {
                'statusCode': 500,
                'body': {'error': 'CloudWatch logging not configured', 'message': 'CloudWatch logging is not configured for Bedrock'}
            }
        
        # Check if guardrails exist (optional - just for logging)
        try:
            guardrails_count = len(bedrock.list_guardrails().get('guardrails', []))
            logger.info(f"Found {guardrails_count} guardrails in account")
        except Exception as e:
            logger.warning(f"Could not list guardrails: {str(e)}")
            guardrails_count = 0
        
        # Create single account-level metric filter
        filter_success, filter_name, metric_name = create_account_metric_filter(
            log_group_name, metric_namespace
        )
        
        if not filter_success:
            return {
                'statusCode': 500,
                'body': {'error': 'Failed to create account-level metric filter', 'message': 'Remediation failed'}
            }
        
        # Create single account-level alarm
        alarm_success, alarm_name = create_account_alarm(
            metric_name, metric_namespace, alarm_name_prefix, alarm_threshold, sns_topic_arn
        )
        
        if not alarm_success:
            return {
                'statusCode': 500,
                'body': {'error': 'Failed to create account-level alarm', 'message': 'Remediation failed'}
            }
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Account-level remediation completed successfully',
                'guardrailsCount': guardrails_count,
                'createdMetricFilter': filter_name,
                'createdAlarm': alarm_name,
                'metricNamespace': metric_namespace,
                'alarmThreshold': alarm_threshold
            }
        }
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        return {
            'statusCode': 500,
            'body': {'error': str(e), 'message': 'Account-level remediation failed'}
        }