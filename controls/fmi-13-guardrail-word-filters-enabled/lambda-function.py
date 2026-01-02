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
            'blocked_words': rule_parameters.get('BlockedWords', '').split(',') if rule_parameters.get('BlockedWords') and rule_parameters.get('BlockedWords') != 'null' else [],
            'managed_word_lists': rule_parameters.get('ManagedWordLists', '').split(',') if rule_parameters.get('ManagedWordLists') and rule_parameters.get('ManagedWordLists') != 'null' else [],
            'input_action': rule_parameters.get('InputAction') if rule_parameters.get('InputAction') != 'null' else None,
            'output_action': rule_parameters.get('OutputAction') if rule_parameters.get('OutputAction') != 'null' else None,
            'required_tags': {}
        }
        
        # Clean up empty strings from lists
        params['blocked_words'] = [word.strip() for word in params['blocked_words'] if word.strip()]
        params['managed_word_lists'] = [wl.strip() for wl in params['managed_word_lists'] if wl.strip()]
        
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

def validate_word_policy(bedrock, guardrail_id, params):
    """Validate word policy configuration"""
    try:
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"Guardrail {guardrail_id} has keys: {list(guardrail.keys())}")
        
        issues = []
        
        # Check if word policy is configured at all
        word_policy = guardrail.get('wordPolicy')
        logger.info(f"Word policy exists for {guardrail_id}: {word_policy is not None}")
        
        if not word_policy:
            logger.info(f"No word policy found for guardrail {guardrail_id}")
            issues.append("Word policy not configured in guardrail")
            return issues
        
        words_config = word_policy.get('words', [])
        managed_word_lists_config = word_policy.get('managedWordLists', [])
        
        logger.info(f"Found {len(words_config)} blocked words and {len(managed_word_lists_config)} managed word lists in guardrail {guardrail_id}")
        
        # Always validate that word policy has actual configuration
        if not words_config and not managed_word_lists_config:
            issues.append("Word policy exists but has no words or managed word lists configured")
            return issues
        
        # If no specific parameters are provided, validate that words/lists exist (already checked above)
        if not params['blocked_words'] and not params['managed_word_lists']:
            return issues
        
        # Validate blocked words
        if params['blocked_words']:
            configured_words = []
            issues_found = []
            
            for word_config in words_config:
                word_text = word_config.get('text', '').lower()
                if word_text not in [w.lower() for w in params['blocked_words']]:
                    continue
                
                # Check if word is enabled
                input_enabled = word_config.get('inputEnabled') is True
                output_enabled = word_config.get('outputEnabled') is True
                
                if not (input_enabled or output_enabled):
                    issues_found.append(f"'{word_text}' not enabled")
                    continue
                
                # Check actions
                word_valid = True
                word_issues = []
                
                if input_enabled and params['input_action'] and word_config.get('inputAction') != params['input_action']:
                    word_valid = False
                    word_issues.append(f"input action {word_config.get('inputAction')}")
                
                if output_enabled and params['output_action'] and word_config.get('outputAction') != params['output_action']:
                    word_valid = False
                    word_issues.append(f"output action {word_config.get('outputAction')}")
                
                if word_valid:
                    configured_words.append(word_text)
                elif word_issues:
                    issues_found.append(f"'{word_text}': {', '.join(word_issues)}")
            
            # Report missing or misconfigured words
            missing_words = set([w.lower() for w in params['blocked_words']]) - set(configured_words)
            if missing_words or issues_found:
                if issues_found:
                    issues.append(f"Blocked word issues: {'; '.join(issues_found)}")
                if missing_words:
                    issues.append(f"Missing blocked words: {', '.join(missing_words)}")
        
        # Validate managed word lists
        if params['managed_word_lists']:
            configured_lists = []
            issues_found = []
            
            for list_config in managed_word_lists_config:
                list_type = list_config.get('type')
                if list_type not in params['managed_word_lists']:
                    continue
                
                # Check if list is enabled
                input_enabled = list_config.get('inputEnabled') is True
                output_enabled = list_config.get('outputEnabled') is True
                
                if not (input_enabled or output_enabled):
                    issues_found.append(f"{list_type} not enabled")
                    continue
                
                # Check actions
                list_valid = True
                list_issues = []
                
                if input_enabled and params['input_action'] and list_config.get('inputAction') != params['input_action']:
                    list_valid = False
                    list_issues.append(f"input action {list_config.get('inputAction')}")
                
                if output_enabled and params['output_action'] and list_config.get('outputAction') != params['output_action']:
                    list_valid = False
                    list_issues.append(f"output action {list_config.get('outputAction')}")
                
                if list_valid:
                    configured_lists.append(list_type)
                elif list_issues:
                    issues_found.append(f"{list_type}: {', '.join(list_issues)}")
            
            # Report missing or misconfigured managed word lists
            missing_lists = set(params['managed_word_lists']) - set(configured_lists)
            if missing_lists or issues_found:
                if issues_found:
                    issues.append(f"Managed word list issues: {'; '.join(issues_found)}")
                if missing_lists:
                    issues.append(f"Missing managed word lists: {', '.join(missing_lists)}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating word policy: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-13: AWS Config rule to validate Bedrock guardrail word policy"""
    logger.info("FMI-13: Starting guardrail word policy validation")
    
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
                    validation_issues = validate_word_policy(bedrock, guardrail_id, params)
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
                        annotation = "Word filtering not configured"
                    elif 'no words or managed word lists' in ' '.join(issues).lower():
                        annotation = "No word filters configured"
                    elif 'missing blocked words' in ' '.join(issues).lower():
                        annotation = "Missing required word filters"
                    elif 'word issues' in ' '.join(issues).lower():
                        annotation = "Incorrect word filter settings"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "Word filtering configuration issues"

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