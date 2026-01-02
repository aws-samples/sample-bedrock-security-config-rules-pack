import boto3
import json
import logging
import traceback

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def parse_config_parameters(event):
    """Parse configuration parameters from Config rule"""
    try:
        rule_parameters = event.get('ruleParameters', {})
        
        if isinstance(rule_parameters, str):
            rule_parameters = json.loads(rule_parameters)
        
        params = {
            'guardrail_name': rule_parameters.get('GuardrailName') if rule_parameters.get('GuardrailName') != 'null' else None,
            'topic_filters': rule_parameters.get('TopicFilters', '').split(',') if rule_parameters.get('TopicFilters') and rule_parameters.get('TopicFilters') != 'null' else [],
            'topic_filter_action': rule_parameters.get('TopicFilterAction'),
            'input_action': rule_parameters.get('InputAction') if rule_parameters.get('InputAction') != 'null' else None,
            'output_action': rule_parameters.get('OutputAction') if rule_parameters.get('OutputAction') != 'null' else None,
            'example': rule_parameters.get('Example') if rule_parameters.get('Example') != 'null' else None,
            'required_tags': {}
        }
        
        # Parse required tags
        required_tags_str = rule_parameters.get('RequiredTags', '')
        if required_tags_str and required_tags_str != 'null':
            for tag_pair in required_tags_str.split(','):
                if '=' in tag_pair:
                    key, value = tag_pair.split('=', 1)
                    params['required_tags'][key.strip()] = value.strip()
        
        logger.info(f"Parsed parameters: {json.dumps(params, default=str)}")
        return params
    except Exception as e:
        logger.error(f"Error parsing parameters: {str(e)}")
        return {}

def filter_guardrails_by_tags(bedrock, guardrails, required_tags):
    """Filter guardrails that match the required tags"""
    if not required_tags:
        return guardrails
    
    filtered_guardrails = []
    for guardrail in guardrails:
        try:
            guardrail_arn = guardrail.get('arn')
            tags_response = bedrock.list_tags_for_resource(resourceARN=guardrail_arn)
            existing_tags = {tag['key']: tag['value'] for tag in tags_response.get('tags', [])}
            
            matches = True
            for required_key, required_value in required_tags.items():
                if existing_tags.get(required_key) != required_value:
                    matches = False
                    break
            
            if matches:
                filtered_guardrails.append(guardrail)
                
        except Exception as e:
            logger.error(f"Error checking tags for guardrail {guardrail.get('name')}: {str(e)}")
    
    return filtered_guardrails

def validate_topic_filters(bedrock, guardrail_id, params):
    """Validate topic filter configuration"""
    try:
        
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"response Config: {json.dumps(guardrail, default=str)}")
       
        issues = []
        
        # Check if topic policy has topics configured
        topic_policy = guardrail.get('topicPolicy')
        logger.info(f"Topic policy exists for {guardrail_id}: {topic_policy is not None}")
        
        if not topic_policy:
            logger.info(f"No topic policy found for guardrail {guardrail_id}")
            issues.append("Topic policy not configured in guardrail")
            return issues
        
        topics_config = topic_policy.get('topics', [])
        logger.info(f"Found {len(topics_config)} topics in guardrail {guardrail_id}")
        
        if not topics_config:
            logger.info(f"No topics configured in topic policy for {guardrail_id}")
            issues.append("No topics configured in topic policy")
            return issues
        
        # If no specific topic filters are specified, validate that topics exist (already checked above)
        if not params['topic_filters']:
            return issues  # Topics exist, so we're compliant
        
        found_topics = set()
        for topic_config in topics_config:
            topic_name = topic_config.get('name')
            topic_type = topic_config.get('type')
            input_enabled = topic_config.get('inputEnabled', False)
            output_enabled = topic_config.get('outputEnabled', False)
            input_action = topic_config.get('inputAction', 'NONE')
            output_action = topic_config.get('outputAction', 'NONE')
            
            # Check if topic is configured and enabled for filtering
            if (topic_name in params['topic_filters'] and 
                topic_type == 'DENY' and 
                (input_enabled or output_enabled)):
                
                # Validate input action if input is enabled
                input_valid = True
                if input_enabled and params['input_action']:
                    input_valid = input_action == params['input_action']
                
                # Validate output action if output is enabled
                output_valid = True
                if output_enabled and params['output_action']:
                    output_valid = output_action == params['output_action']
                
                # Validate example if specified
                example_valid = True
                if params['example']:
                    topic_examples = topic_config.get('examples', [])
                    example_valid = params['example'] in topic_examples
                
                if input_valid and output_valid and example_valid:
                    found_topics.add(topic_name)
        
        missing_topics = set(params['topic_filters']) - found_topics
        if missing_topics:
            # Check if topics exist but have wrong actions
            action_issues = []
            for topic_config in topics_config:
                topic_name = topic_config.get('name')
                if topic_name in missing_topics:
                    input_enabled = topic_config.get('inputEnabled', False)
                    output_enabled = topic_config.get('outputEnabled', False)
                    input_action = topic_config.get('inputAction', 'NONE')
                    output_action = topic_config.get('outputAction', 'NONE')
                    
                    action_problems = []
                    if input_enabled and params['input_action'] and input_action != params['input_action']:
                        action_problems.append(f"input action is {input_action}, expected {params['input_action']}")
                    if output_enabled and params['output_action'] and output_action != params['output_action']:
                        action_problems.append(f"output action is {output_action}, expected {params['output_action']}")
                    if params['example']:
                        topic_examples = topic_config.get('examples', [])
                        if params['example'] not in topic_examples:
                            action_problems.append(f"example '{params['example']}' not found in topic examples")
                    
                    if action_problems:
                        action_issues.append(f"{topic_name}: {', '.join(action_problems)}")
            
            if action_issues:
                issues.append(f"Topic action mismatches: {'; '.join(action_issues)}")
            else:
                issues.append(f"Missing topic filters: {', '.join(missing_topics)}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating topic filters: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-11: AWS Config rule to validate Bedrock guardrail topic filters"""
    logger.info("FMI-11: Starting guardrail topic filters validation")
    
    config = boto3.client('config')
    
    try:
        invoking_event = json.loads(event['invokingEvent'])
        account_id = event['accountId']
        result_token = event.get('resultToken', '')
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f'Event parsing error: {str(e)}'}

    params = parse_config_parameters(event)
    bedrock = boto3.client('bedrock')
    
    try:
        logger.info("Listing guardrails...")
        guardrails_response = bedrock.list_guardrails()
        guardrails = guardrails_response.get('guardrails', [])
        logger.info(f"Found {len(guardrails)} guardrails: {json.dumps(guardrails, default=str)}")
        
        if not guardrails:
            compliance_type = 'NON_COMPLIANT'
            annotation = 'No guardrails configured'
        else:
            # Filter by tags and name
            target_guardrails = guardrails
            if params['required_tags']:
                target_guardrails = filter_guardrails_by_tags(bedrock, target_guardrails, params['required_tags'])
            
            if params['guardrail_name']:
                target_guardrails = [g for g in target_guardrails if g.get('name') == params['guardrail_name']]
            
            logger.info(f"Target guardrails: {json.dumps(target_guardrails, default=str)}")
            if not target_guardrails:
                compliance_type = 'NON_COMPLIANT'
                annotation = 'No guardrails match the specified criteria'
            else:
                compliant_guardrails = []
                issues = []
                
                for guardrail in target_guardrails:
                    guardrail_name = guardrail.get('name')
                    guardrail_id = guardrail.get('id')
                    
                    if guardrail.get('status') != 'READY':
                        logger.warning(f"Guardrail {guardrail_name} not ready")
                        issues.append(f"{guardrail_name}: Not ready")
                        continue
                    
                    logger.info(f"Validating guardrail: {guardrail_name} ({guardrail_id})")
                    validation_issues = validate_topic_filters(bedrock, guardrail_id, params)
                    if validation_issues:
                        issues.extend([f"{guardrail_name}: {issue}" for issue in validation_issues])
                    else:
                        compliant_guardrails.append(guardrail_name)
                
                if compliant_guardrails:
                    compliance_type = 'COMPLIANT'
                    annotation = f"Compliant guardrails: {', '.join(compliant_guardrails)}"
                    logger.info(f"Result: COMPLIANT - {len(compliant_guardrails)} guardrails")
                else:
                    compliance_type = 'NON_COMPLIANT'
                    # Log full details but keep annotation short
                    logger.warning(f"NON_COMPLIANT - {len(issues)} issues found:")
                    for i, issue in enumerate(issues):
                        logger.warning(f"  Issue {i+1}: {issue}")
                    
                    # Create focused annotation for Config
                    if 'not configured' in ' '.join(issues).lower():
                        annotation = "Topic filtering not configured"
                    elif 'no topics configured' in ' '.join(issues).lower():
                        annotation = "No topic filters configured"
                    elif 'missing topic filters' in ' '.join(issues).lower():
                        annotation = "Missing required topic filters"
                    elif 'action mismatch' in ' '.join(issues).lower():
                        annotation = "Incorrect topic filter actions"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "Topic filtering configuration issues"

    except Exception as e:
        logger.error(f"Error evaluating guardrails: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Evaluation error: {str(e)}'

    # Submit results
    try:
        if result_token:
            config.put_evaluations(
                Evaluations=[{
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': account_id,
                    'ComplianceType': compliance_type,
                    'Annotation': annotation,
                    'OrderingTimestamp': invoking_event['notificationCreationTime']
                }],
                ResultToken=result_token
            )
    except Exception as e:
        logger.error(f"Error submitting results: {str(e)}")

    return {'compliance_type': compliance_type, 'annotation': annotation}