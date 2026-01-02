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
            'automated_reasoning_policies': rule_parameters.get('AutomatedReasoningPolicies', '').split(',') if rule_parameters.get('AutomatedReasoningPolicies') and rule_parameters.get('AutomatedReasoningPolicies') != 'null' else [],
            'min_confidence_threshold': float(rule_parameters.get('MinConfidenceThreshold')) if rule_parameters.get('MinConfidenceThreshold') and rule_parameters.get('MinConfidenceThreshold') != 'null' else None,
            'required_tags': {}
        }
        
        # Clean up empty strings from lists
        params['automated_reasoning_policies'] = [policy.strip() for policy in params['automated_reasoning_policies'] if policy.strip()]
        
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

def validate_automated_reasoning_policy(bedrock, guardrail_id, params):
    """Validate automated reasoning policy configuration"""
    try:
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"Guardrail {guardrail_id} has keys: {list(guardrail.keys())}")
        
        issues = []
        
        # Check if automated reasoning policy is configured at all
        automated_reasoning_policy = guardrail.get('automatedReasoningPolicy')
        logger.info(f"Automated reasoning policy exists for {guardrail_id}: {automated_reasoning_policy is not None}")
        
        if not automated_reasoning_policy:
            logger.info(f"No automated reasoning policy found for guardrail {guardrail_id}")
            issues.append("Automated reasoning policy not configured in guardrail")
            return issues
        
        policies_config = automated_reasoning_policy.get('policies', [])
        confidence_threshold = automated_reasoning_policy.get('confidenceThreshold')
        
        logger.info(f"Found {len(policies_config)} automated reasoning policies and confidence threshold {confidence_threshold} in guardrail {guardrail_id}")
        
        # Always validate that automated reasoning policy has actual configuration
        if not policies_config and confidence_threshold is None:
            issues.append("Automated reasoning policy exists but has no policies or confidence threshold configured")
            return issues
        
        # If no specific parameters are provided, validate that policies/threshold exist (already checked above)
        if not params['automated_reasoning_policies'] and params['min_confidence_threshold'] is None:
            return issues
        
        # Validate required policies
        if params['automated_reasoning_policies']:
            configured_policies = []
            missing_policies = []
            
            # Check if all required policies are present
            for automated_reasoning_policy in params['automated_reasoning_policies']:
                policy_found = False
                for configured_policy in policies_config:
                    # Check if the policy matches (could be ARN or name)
                    if (configured_policy == automated_reasoning_policy or 
                        configured_policy.endswith(f"/{automated_reasoning_policy}") or
                        automated_reasoning_policy in configured_policy):
                        configured_policies.append(automated_reasoning_policy)
                        policy_found = True
                        break
                
                if not policy_found:
                    missing_policies.append(automated_reasoning_policy)
            
            if missing_policies:
                issues.append(f"Missing required automated reasoning policies: {', '.join(missing_policies)}")
        
        # Validate confidence threshold
        if params['min_confidence_threshold'] is not None:
            if confidence_threshold is None:
                issues.append("Confidence threshold not configured")
            elif confidence_threshold < params['min_confidence_threshold']:
                issues.append(f"Confidence threshold {confidence_threshold} below minimum {params['min_confidence_threshold']}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating automated reasoning policy: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-16: AWS Config rule to validate Bedrock guardrail automated reasoning policy"""
    logger.info("FMI-16: Starting guardrail automated reasoning policy validation")
    
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
                    validation_issues = validate_automated_reasoning_policy(bedrock, guardrail_id, params)
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
                        annotation = "Automated reasoning not configured"
                    elif 'no policies or confidence threshold' in ' '.join(issues).lower():
                        annotation = "No reasoning policies configured"
                    elif 'missing policies' in ' '.join(issues).lower():
                        annotation = "Missing required reasoning policies"
                    elif 'confidence threshold' in ' '.join(issues).lower():
                        annotation = "Incorrect confidence threshold"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "Automated reasoning configuration issues"

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