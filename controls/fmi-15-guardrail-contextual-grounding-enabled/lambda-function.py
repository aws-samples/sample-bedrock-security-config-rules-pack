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
            'filter_types': rule_parameters.get('FilterTypes', '').split(',') if rule_parameters.get('FilterTypes') and rule_parameters.get('FilterTypes') != 'null' else [],
            'grounding_threshold': float(rule_parameters.get('GroundingThreshold')) if rule_parameters.get('GroundingThreshold') and rule_parameters.get('GroundingThreshold') != 'null' else None,
            'relevance_threshold': float(rule_parameters.get('RelevanceThreshold')) if rule_parameters.get('RelevanceThreshold') and rule_parameters.get('RelevanceThreshold') != 'null' else None,
            'filter_action': rule_parameters.get('FilterAction') if rule_parameters.get('FilterAction') != 'null' else None,
            'required_tags': {}
        }
        
        # Clean up empty strings from lists
        params['filter_types'] = [filter_type.strip() for filter_type in params['filter_types'] if filter_type.strip()]
        
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

def validate_contextual_grounding_policy(bedrock, guardrail_id, params):
    """Validate contextual grounding policy configuration"""
    try:
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"Guardrail {guardrail_id} has keys: {list(guardrail.keys())}")
        
        issues = []
        
        # Check if contextual grounding policy is configured at all
        contextual_grounding_policy = guardrail.get('contextualGroundingPolicy')
        logger.info(f"Contextual grounding policy exists for {guardrail_id}: {contextual_grounding_policy is not None}")
        
        if not contextual_grounding_policy:
            logger.info(f"No contextual grounding policy found for guardrail {guardrail_id}")
            issues.append("Contextual grounding policy not configured in guardrail")
            return issues
        
        filters_config = contextual_grounding_policy.get('filters', [])
        logger.info(f"Found {len(filters_config)} contextual grounding filters in guardrail {guardrail_id}")
        
        if not filters_config:
            logger.info(f"No contextual grounding filters configured in policy for {guardrail_id}")
            issues.append("No contextual grounding filters configured in policy")
            return issues
        
        # If no specific filter types are provided, validate that filters exist (already checked above)
        if not params['filter_types']:
            return issues  # Contextual grounding filters exist, so we're compliant
        
        configured_filters = []
        issues_found = []
        
        for filter_config in filters_config:
            filter_type = filter_config.get('type')
            if filter_type not in params['filter_types']:
                continue
                
            # Check if filter is enabled
            enabled = filter_config.get('enabled') is True
            
            if not enabled:
                issues_found.append(f"{filter_type} not enabled")
                continue
            
            # Check requirements - all must pass for filter to be compliant
            filter_valid = True
            filter_issues = []
            
            # Check threshold requirements
            current_threshold = filter_config.get('threshold')
            if current_threshold is None:
                filter_valid = False
                filter_issues.append("threshold not set")
            else:
                # Check grounding threshold
                if filter_type == 'GROUNDING' and params['grounding_threshold'] is not None:
                    if current_threshold < params['grounding_threshold']:
                        filter_valid = False
                        filter_issues.append(f"threshold {current_threshold} below minimum {params['grounding_threshold']}")
                
                # Check relevance threshold
                if filter_type == 'RELEVANCE' and params['relevance_threshold'] is not None:
                    if current_threshold < params['relevance_threshold']:
                        filter_valid = False
                        filter_issues.append(f"threshold {current_threshold} below minimum {params['relevance_threshold']}")
            
            # Check action
            if params['filter_action'] and filter_config.get('action') != params['filter_action']:
                filter_valid = False
                filter_issues.append(f"action {filter_config.get('action')}")
            
            if filter_valid:
                configured_filters.append(filter_type)
            elif filter_issues:
                issues_found.append(f"{filter_type}: {', '.join(filter_issues)}")
        
        # Report missing or misconfigured filters
        missing_filters = set(params['filter_types']) - set(configured_filters)
        if missing_filters or issues_found:
            if issues_found:
                issues.append(f"Contextual grounding filter issues: {'; '.join(issues_found)}")
            if missing_filters:
                issues.append(f"Missing contextual grounding filters: {', '.join(missing_filters)}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating contextual grounding policy: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-15: AWS Config rule to validate Bedrock guardrail contextual grounding policy"""
    logger.info("FMI-15: Starting guardrail contextual grounding policy validation")
    
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
            
            logger.info(f"Evaluating {len(target_guardrails)} guardrails")
            
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
                    validation_issues = validate_contextual_grounding_policy(bedrock, guardrail_id, params)
                    logger.info(f"Validation issues: {json.dumps(validation_issues, default=str)}")
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
                        annotation = "Contextual grounding not configured"
                    elif 'no contextual grounding filters' in ' '.join(issues).lower():
                        annotation = "No grounding filters configured"
                    elif 'missing filter types' in ' '.join(issues).lower():
                        annotation = "Missing required grounding filters"
                    elif 'filter issues' in ' '.join(issues).lower():
                        annotation = "Incorrect grounding filter settings"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "Contextual grounding configuration issues"

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