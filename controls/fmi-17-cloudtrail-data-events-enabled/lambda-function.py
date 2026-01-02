import boto3
import json
import datetime
import logging
import traceback
import re

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS Config client
logger.info("Initializing AWS Config client")
config = boto3.client('config')

# Initialize CloudTrail client
logger.info("Initializing AWS CloudTrail client")
cloudtrail = boto3.client('cloudtrail')

# Default resource types if none provided
DEFAULT_RESOURCE_TYPES = {'AWS::Bedrock::Model','AWS::Bedrock::AsyncInvoke','AWS::Bedrock::Guardrail','AWS::Bedrock::AgentAlias','AWS::Bedrock::FlowAlias','AWS::Bedrock::InlineAgent','AWS::Bedrock::KnowledgeBase','AWS::Bedrock::PromptVersion','AWS::Bedrock::Session','AWS::Bedrock::FlowExecution'}

def create_evaluation(resource_id, resource_type, compliance_type, annotation):
    """Create an evaluation result."""
    return {
        'ComplianceResourceType': resource_type,
        'ComplianceResourceId': resource_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation[:256],  # Truncate to 256 chars
        'OrderingTimestamp': datetime.datetime.utcnow().isoformat()
    }

def validate_resource_types_format(resource_types_param):
    """Validate that resource types parameter follows the correct format."""
    if not resource_types_param:
        return False, "Resource types parameter is empty"
    
    # Pattern for AWS resource types: AWS::Service::ResourceType
    resource_type_pattern = re.compile(r'^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$')
    
    # Split by comma and validate each resource type
    resource_types = [rt.strip() for rt in resource_types_param.split(',') if rt.strip()]
    
    if not resource_types:
        return False, "No valid resource types found after parsing"
    
    for resource_type in resource_types:
        if not resource_type_pattern.match(resource_type):
            return False, f"Invalid resource type format: {resource_type}. Must be AWS::Service::ResourceType"
    
    return True, f"Validated {len(resource_types)} resource types"

def handler(event, context):
    """
    AWS Config rule to check if CloudTrail data events are enabled for Amazon Bedrock.
    Control ID: FMI-17 - bedrock-cloudtrail-data-events
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        logger.info("Parsing invokingEvent")
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        logger.info(f"Invoking event parsed: {json.dumps(invoking_event, default=str)}")
    except Exception as e:
        logger.error(f"Error parsing invokingEvent: {str(e)}")
        logger.error(traceback.format_exc())
        invoking_event = {}

    # Get account ID
    account_id = event.get('accountId')
    if not account_id:
        logger.info("Account ID not found in event, extracting from Lambda context")
        account_id = context.invoked_function_arn.split(':')[4]
    logger.info(f"Account ID: {account_id}")

    # Get result token
    result_token = event.get('resultToken')
    logger.info(f"Result token available: {bool(result_token)}")

    # Get rule parameters
    rule_parameters = event.get('ruleParameters', '{}')
    try:
        rule_params = json.loads(rule_parameters) if rule_parameters else {}
        logger.info(f"Rule parameters: {json.dumps(rule_params)}")
    except Exception as e:
        logger.error(f"Error parsing rule parameters: {str(e)}")
        rule_params = {}

    # Get resource types from parameters or use defaults
    resource_types_param = rule_params.get('resourceTypes', '')
    if resource_types_param:
        # Validate resource types format
        is_valid, validation_message = validate_resource_types_format(resource_types_param)
        if not is_valid:
            logger.error(f"Resource types validation failed: {validation_message}")
            return create_evaluation(account_id, 'AWS::::Account', 'NON_COMPLIANT', 
                                   f'Invalid configuration: {validation_message}')
        
        # Parse comma-separated resource types
        required_resource_types = set(rt.strip() for rt in resource_types_param.split(',') if rt.strip())
        logger.info(f"Using resource types from parameters: {required_resource_types}")
        logger.info(validation_message)
        
        # Validate that we have at least one resource type
        if not required_resource_types:
            logger.error("No valid resource types found in parameters after parsing")
            return create_evaluation(account_id, 'AWS::::Account', 'NON_COMPLIANT', 
                                   'Invalid configuration: No valid resource types specified in parameters')
    else:
        required_resource_types = DEFAULT_RESOURCE_TYPES
        logger.info(f"Using default resource types: {required_resource_types}")
    
    # Final validation to ensure we have resource types to check
    if not required_resource_types:
        logger.error("No resource types available for evaluation")
        return create_evaluation(account_id, 'AWS::::Account', 'NON_COMPLIANT', 
                               'Invalid configuration: No resource types available for evaluation')

    try:
        # Get all trails
        logger.info("Calling CloudTrail describe_trails API")
        trails_response = cloudtrail.describe_trails(includeShadowTrails=True)
        logger.info(f"CloudTrail API response: {json.dumps(trails_response, default=str)}")
        
        trails = trails_response.get('trailList', [])
        logger.info(f"Found {len(trails)} trails")

        #No trails found. Return NON_COMPLIANT
        if not trails:
            logger.info("No trails found. Returning NON_COMPLIANT")
            return create_evaluation(account_id, 'AWS::::Account', 'NON_COMPLIANT', 'No CloudTrail trails found')
        
        # Check if all required resource types have data events enabled
        configured_resource_types = set()
        trail_details = []
        
        for trail in trails:
            trail_name = trail.get('Name')
            trail_arn = trail.get('TrailARN')
            
            # Skip trails that are not multi-region or not logging
            if not trail.get('IsMultiRegionTrail', False):
                logger.info(f"Trail {trail_name} is not multi-region, skipping")
                continue
                
            # Check if trail is logging
            try:
                status_response = cloudtrail.get_trail_status(Name=trail_arn)
                if not status_response.get('IsLogging', False):
                    logger.info(f"Trail {trail_name} is not logging, skipping")
                    continue
            except Exception as e:
                # Handle cases where trail exists in list but is not accessible or doesn't exist
                logger.warning(f"Unable to get status for trail {trail_name}: {str(e)}")
                if 'TrailNotFoundException' in str(e) or 'AccessDenied' in str(e):
                    logger.info(f"Trail {trail_name} not found or access denied, skipping")
                    continue
                else:
                    # For other errors, log but continue to next trail
                    logger.error(f"Unexpected error getting trail status for {trail_name}: {str(e)}")
                    continue
            
            # Get event selectors for the trail
            logger.info(f"Getting event selectors for trail: {trail_name}")
            try:
                event_selectors_response = cloudtrail.get_event_selectors(TrailName=trail_arn)
                logger.info(f"Event selectors response: {json.dumps(event_selectors_response, default=str)}")
                
                # Check advanced event selectors for required resource types
                advanced_event_selectors = event_selectors_response.get('AdvancedEventSelectors', [])
                
                for selector in advanced_event_selectors:
                    field_selectors = selector.get('FieldSelectors', [])
                    
                    # Check if this selector includes data events
                    includes_data_events = False
                    selector_resource_types = set()
                    
                    for field in field_selectors:
                        field_name = field.get('Field')
                        field_values = field.get('Equals', [])
                        
                        if field_name == 'eventCategory' and 'Data' in field_values:
                            includes_data_events = True
                        
                        # Collect resource types from this selector
                        if field_name == 'resources.type':
                            for value in field_values:
                                if value in required_resource_types:
                                    selector_resource_types.add(value)
                    
                    # If this selector has data events and required resource types, add them to configured set
                    if includes_data_events and selector_resource_types:
                        configured_resource_types.update(selector_resource_types)
                        for resource_type in selector_resource_types:
                            logger.info(f"Found data events configured for resource type: {resource_type} in trail: {trail_name}")
                
            except Exception as e:
                logger.error(f"Error getting event selectors for trail {trail_name}: {str(e)}")
                logger.error(traceback.format_exc())
        
        # Check if all required resource types are configured
        missing_resource_types = required_resource_types - configured_resource_types
        
        if configured_resource_types:
            trail_details.append(f"Found data events configured for {len(configured_resource_types)} resource types")
        
        logger.info(f"Required resource types: {len(required_resource_types)}")
        logger.info(f"Configured resource types: {len(configured_resource_types)}")
        logger.info(f"Missing resource types: {len(missing_resource_types)}")
        
        # Determine compliance based on findings
        if len(missing_resource_types) == 0:
            compliance_type = 'COMPLIANT'
            annotation = f"CloudTrail data events are enabled for all {len(required_resource_types)} required resource types. {'; '.join(trail_details)}"
        else:
            compliance_type = 'NON_COMPLIANT'
            annotation = f'CloudTrail data events missing for {len(missing_resource_types)} of {len(required_resource_types)} required resource types. Configure advanced event selectors to include all resource types.'
    
    except Exception as e:
        logger.error(f"Error checking CloudTrail data events: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error checking CloudTrail data events: {str(e)}'

    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        logger.info("notificationCreationTime not found, using current UTC time")
        ordering_timestamp = datetime.datetime.utcnow().isoformat()
    logger.info(f"Ordering timestamp: {ordering_timestamp}")

    # Create evaluation result
    evaluation = create_evaluation(account_id, 'AWS::::Account', compliance_type, annotation)
    
    # Put evaluation results
    if result_token:
        logger.info("Putting evaluation results to AWS Config")
        try:
            evaluation_result = config.put_evaluations(
                Evaluations=[evaluation],
                ResultToken=result_token
            )
            logger.info(f"Evaluation result: {json.dumps(evaluation_result, default=str)}")
        except Exception as e:
            logger.error(f"Error putting evaluation results: {str(e)}")
            logger.error(traceback.format_exc())
    else:
        logger.warning("No result token available, skipping put_evaluations call")

    logger.info(f"Lambda function completed. Result: {json.dumps(evaluation, default=str)}")
    return evaluation