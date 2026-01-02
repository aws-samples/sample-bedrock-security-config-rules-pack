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
            'content_filters': rule_parameters.get('ContentFilters', '').split(',') if rule_parameters.get('ContentFilters') and rule_parameters.get('ContentFilters') != 'null' else [],
            'input_strength': rule_parameters.get('InputStrength') if rule_parameters.get('InputStrength') != 'null' else None,
            'output_strength': rule_parameters.get('OutputStrength') if rule_parameters.get('OutputStrength') != 'null' else None,
            'input_action': rule_parameters.get('InputAction') if rule_parameters.get('InputAction') != 'null' else None,
            'output_action': rule_parameters.get('OutputAction') if rule_parameters.get('OutputAction') != 'null' else None,
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

def validate_content_filters(bedrock, guardrail_id, params):
    """Validate content filter configuration"""
    try:
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"Guardrail {guardrail_id} has keys: {list(guardrail.keys())}")
        
        issues = []
        
        # Check if content policy is configured at all
        content_policy = guardrail.get('contentPolicy')
        logger.info(f"Content policy exists for {guardrail_id}: {content_policy is not None}")
        
        if not content_policy:
            logger.info(f"No content policy found for guardrail {guardrail_id}")
            issues.append("Content policy not configured in guardrail")
            return issues
        
        filters_config = content_policy.get('filters', [])
        logger.info(f"Found {len(filters_config)} content filters in guardrail {guardrail_id}")
        
        if not filters_config:
            logger.info(f"No content filters configured in content policy for {guardrail_id}")
            issues.append("No content filters configured in content policy")
            return issues
        
        # If no specific content filters are specified, validate that filters exist (already checked above)
        if not params['content_filters']:
            return issues  # Content filters exist, so we're compliant
        
        strength_levels = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        compliant_filters = []
        issues_found = []
        
        for filter_config in filters_config:
            filter_type = filter_config.get('type')
            if filter_type not in params['content_filters']:
                continue
                
            # Check if filter is enabled
            input_enabled = filter_config.get('inputEnabled') is True
            output_enabled = filter_config.get('outputEnabled') is True
            
            if not (input_enabled or output_enabled):
                issues_found.append(f"{filter_type} not enabled")
                continue
            
            # Check requirements - all must pass for filter to be compliant
            filter_valid = True
            filter_issues = []
            
            # Input validation
            if input_enabled and params['input_strength']:
                current = filter_config.get('inputStrength')
                if not current or strength_levels.get(current, 0) < strength_levels.get(params['input_strength'], 0):
                    filter_valid = False
                    filter_issues.append(f"input strength {current or 'missing'}")
            
            if input_enabled and params['input_action'] and filter_config.get('inputAction') != params['input_action']:
                filter_valid = False
                filter_issues.append(f"input action {filter_config.get('inputAction')}")
            
            # Output validation  
            if output_enabled and params['output_strength']:
                current = filter_config.get('outputStrength')
                if not current or strength_levels.get(current, 0) < strength_levels.get(params['output_strength'], 0):
                    filter_valid = False
                    filter_issues.append(f"output strength {current or 'missing'}")
            
            if output_enabled and params['output_action'] and filter_config.get('outputAction') != params['output_action']:
                filter_valid = False
                filter_issues.append(f"output action {filter_config.get('outputAction')}")
            
            if filter_valid:
                compliant_filters.append(filter_type)
            elif filter_issues:
                issues_found.append(f"{filter_type}: {', '.join(filter_issues)}")
        
        # Report missing or misconfigured filters
        missing = set(params['content_filters']) - set(compliant_filters)
        if missing or issues_found:
            if issues_found:
                issues.append(f"Content filter issues: {'; '.join(issues_found)}")
            if missing:
                issues.append(f"Missing filters: {', '.join(missing)}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating content filters: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-12: AWS Config rule to validate Bedrock guardrail content filters"""
    logger.info("FMI-12: Starting guardrail content filters validation")
    
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
                    validation_issues = validate_content_filters(bedrock, guardrail_id, params)
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
                        annotation = "Content filtering not configured"
                    elif 'no content filters' in ' '.join(issues).lower():
                        annotation = "No content filters configured"
                    elif 'missing filters' in ' '.join(issues).lower():
                        annotation = "Missing required content filters"
                    elif 'filter issues' in ' '.join(issues).lower():
                        annotation = "Incorrect content filter settings"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "Content filtering configuration issues"

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