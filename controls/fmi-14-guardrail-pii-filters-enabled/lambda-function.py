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
            'pii_entities': rule_parameters.get('PIIEntities', '').split(',') if rule_parameters.get('PIIEntities') and rule_parameters.get('PIIEntities') != 'null' else [],
            'pii_action': rule_parameters.get('PIIAction') if rule_parameters.get('PIIAction') != 'null' else None,
            'input_action': rule_parameters.get('InputAction') if rule_parameters.get('InputAction') != 'null' else None,
            'output_action': rule_parameters.get('OutputAction') if rule_parameters.get('OutputAction') != 'null' else None,
            'custom_regex_patterns': [],
            'required_tags': {}
        }
        
        # Clean up empty strings from lists
        params['pii_entities'] = [entity.strip() for entity in params['pii_entities'] if entity.strip()]
        
        # Collect all RegexPattern parameters dynamically
        for key, value in rule_parameters.items():
            if key.startswith('RegexPattern') and value and value != 'null':
                params['custom_regex_patterns'].append(value)
        
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

def validate_sensitive_information_policy(bedrock, guardrail_id, params):
    """Validate sensitive information policy configuration"""
    try:
        logger.info(f"Getting guardrail: {guardrail_id}")
        guardrail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
        logger.info(f"Guardrail {guardrail_id} has keys: {list(guardrail.keys())}")
        
        issues = []
        
        # Check if sensitive information policy is configured at all
        sensitive_info_policy = guardrail.get('sensitiveInformationPolicy')
        logger.info(f"Sensitive information policy exists for {guardrail_id}: {sensitive_info_policy is not None}")
        
        if not sensitive_info_policy:
            logger.info(f"No sensitive information policy found for guardrail {guardrail_id}")
            issues.append("Sensitive information policy not configured in guardrail")
            return issues
        
        pii_entities_config = sensitive_info_policy.get('piiEntities', [])
        regexes_config = sensitive_info_policy.get('regexes', [])
        
        logger.info(f"Found {len(pii_entities_config)} PII entities and {len(regexes_config)} regex patterns in guardrail {guardrail_id}")
        
        # Always validate that sensitive information policy has actual configuration
        if not pii_entities_config and not regexes_config:
            issues.append("Sensitive information policy exists but has no PII entities or regex patterns configured")
            return issues
        
        # If no specific parameters are provided, validate that entities/patterns exist (already checked above)
        if not params.get('pii_entities', []) and not params.get('custom_regex_patterns', []):
            return issues
        
        # Validate PII entities
        if params.get('pii_entities', []):
            logger.info(f"Validating PII entities: {params['pii_entities']}")
            logger.info(f"Configured PII entities in guardrail: {[e.get('type') for e in pii_entities_config]}")
            
            configured_entities = []
            issues_found = []
            
            for entity_config in pii_entities_config:
                entity_type = entity_config.get('type')
                if entity_type not in params['pii_entities']:
                    logger.debug(f"Skipping PII entity {entity_type} - not in required list")
                    continue
                
                logger.info(f"Validating PII entity: {entity_type}")
                logger.info(f"Entity config: {json.dumps(entity_config, default=str)}")
                
                # Check if entity is enabled
                input_enabled = entity_config.get('inputEnabled') is True
                output_enabled = entity_config.get('outputEnabled') is True
                
                if not (input_enabled or output_enabled):
                    logger.warning(f"PII entity {entity_type} is not enabled (input: {input_enabled}, output: {output_enabled})")
                    issues_found.append(f"{entity_type} not enabled")
                    continue
                
                # Check actions
                entity_valid = True
                entity_issues = []
                
                # Check general action (legacy field)
                if params.get('pii_action') and entity_config.get('action') != params['pii_action']:
                    logger.warning(f"PII entity {entity_type} action mismatch: expected {params['pii_action']}, got {entity_config.get('action')}")
                    entity_valid = False
                    entity_issues.append(f"action {entity_config.get('action')}")
                
                # Check input/output specific actions
                if input_enabled and params.get('input_action') and entity_config.get('inputAction') != params['input_action']:
                    logger.warning(f"PII entity {entity_type} input action mismatch: expected {params['input_action']}, got {entity_config.get('inputAction')}")
                    entity_valid = False
                    entity_issues.append(f"input action {entity_config.get('inputAction')}")
                
                if output_enabled and params.get('output_action') and entity_config.get('outputAction') != params['output_action']:
                    logger.warning(f"PII entity {entity_type} output action mismatch: expected {params['output_action']}, got {entity_config.get('outputAction')}")
                    entity_valid = False
                    entity_issues.append(f"output action {entity_config.get('outputAction')}")
                
                if entity_valid:
                    logger.info(f"PII entity {entity_type} is valid")
                    configured_entities.append(entity_type)
                elif entity_issues:
                    logger.warning(f"PII entity {entity_type} validation failed: {', '.join(entity_issues)}")
                    issues_found.append(f"{entity_type}: {', '.join(entity_issues)}")
            
            # Report missing or misconfigured PII entities
            missing_entities = set(params['pii_entities']) - set(configured_entities)
            logger.info(f"Required PII entities: {params['pii_entities']}")
            logger.info(f"Configured PII entities: {configured_entities}")
            logger.info(f"Missing PII entities: {list(missing_entities)}")
            
            if missing_entities or issues_found:
                if issues_found:
                    logger.warning(f"PII entity issues found: {issues_found}")
                    issues.append(f"PII entity issues: {'; '.join(issues_found)}")
                if missing_entities:
                    logger.warning(f"Missing PII entities: {list(missing_entities)}")
                    issues.append(f"Missing PII entities: {', '.join(missing_entities)}")
        
        # Validate custom regex patterns
        if params.get('custom_regex_patterns', []):
            logger.info(f"Validating custom regex patterns: {params['custom_regex_patterns']}")
            logger.info(f"Configured regex patterns in guardrail (names): {[r.get('name') for r in regexes_config]}")
            logger.info(f"Configured regex patterns in guardrail (actual patterns): {[r.get('pattern') for r in regexes_config]}")
            logger.info(f"Full regex configs: {json.dumps(regexes_config, default=str)}")
            
            configured_patterns = []
            issues_found = []
            
            for regex_config in regexes_config:
                pattern_name = regex_config.get('name')
                actual_pattern = regex_config.get('pattern')
                
                logger.info(f"Checking pattern: name='{pattern_name}', pattern='{actual_pattern}'")
                logger.info(f"Required patterns: {params['custom_regex_patterns']}")
                logger.info(f"Pattern match check: '{actual_pattern}' in {params['custom_regex_patterns']} = {actual_pattern in params['custom_regex_patterns']}")
                
                # Compare against the actual regex pattern, not the name
                if actual_pattern not in params['custom_regex_patterns']:
                    logger.warning(f"Pattern '{actual_pattern}' not found in required list {params['custom_regex_patterns']}")
                    continue
                
                logger.info(f"Validating regex pattern: {pattern_name} (pattern: {actual_pattern})")
                logger.info(f"Pattern config: {json.dumps(regex_config, default=str)}")
                
                # Check if pattern is enabled
                input_enabled = regex_config.get('inputEnabled') is True
                output_enabled = regex_config.get('outputEnabled') is True
                
                if not (input_enabled or output_enabled):
                    logger.warning(f"Regex pattern {pattern_name} is not enabled (input: {input_enabled}, output: {output_enabled})")
                    issues_found.append(f"'{pattern_name}' not enabled")
                    continue
                
                # Check actions
                pattern_valid = True
                pattern_issues = []
                
                # Check general action (legacy field)
                if params.get('pii_action') and regex_config.get('action') != params['pii_action']:
                    logger.warning(f"Regex pattern {pattern_name} action mismatch: expected {params['pii_action']}, got {regex_config.get('action')}")
                    pattern_valid = False
                    pattern_issues.append(f"action {regex_config.get('action')}")
                
                # Check input/output specific actions
                if input_enabled and params.get('input_action') and regex_config.get('inputAction') != params['input_action']:
                    logger.warning(f"Regex pattern {pattern_name} input action mismatch: expected {params['input_action']}, got {regex_config.get('inputAction')}")
                    pattern_valid = False
                    pattern_issues.append(f"input action {regex_config.get('inputAction')}")
                
                if output_enabled and params.get('output_action') and regex_config.get('outputAction') != params['output_action']:
                    logger.warning(f"Regex pattern {pattern_name} output action mismatch: expected {params['output_action']}, got {regex_config.get('outputAction')}")
                    pattern_valid = False
                    pattern_issues.append(f"output action {regex_config.get('outputAction')}")
                
                if pattern_valid:
                    logger.info(f"Regex pattern {pattern_name} (pattern: {actual_pattern}) is valid")
                    configured_patterns.append(actual_pattern)  # Store the actual pattern, not the name
                elif pattern_issues:
                    logger.warning(f"Regex pattern {pattern_name} (pattern: {actual_pattern}) validation failed: {', '.join(pattern_issues)}")
                    issues_found.append(f"'{pattern_name}' (pattern: {actual_pattern}): {', '.join(pattern_issues)}")
            
            # Report missing or misconfigured regex patterns
            missing_patterns = set(params['custom_regex_patterns']) - set(configured_patterns)
            logger.info(f"Required regex patterns: {params['custom_regex_patterns']}")
            logger.info(f"Configured regex patterns: {configured_patterns}")
            logger.info(f"Missing regex patterns: {list(missing_patterns)}")
            
            if missing_patterns or issues_found:
                if issues_found:
                    logger.warning(f"Regex pattern issues found: {issues_found}")
                    issues.append(f"Custom regex pattern issues: {'; '.join(issues_found)}")
                if missing_patterns:
                    logger.warning(f"Missing regex patterns: {list(missing_patterns)}")
                    issues.append(f"Missing custom regex patterns: {', '.join(missing_patterns)}")
        
        return issues
        
    except Exception as e:
        logger.error(f"Error validating sensitive information policy: {str(e)}")
        logger.error(f"Stacktrace: {traceback.format_exc()}")
        return [f"Validation error: {str(e)}"]

def handler(event, context):
    """FMI-14: AWS Config rule to validate Bedrock guardrail sensitive information policy"""
    logger.info("FMI-14: Starting guardrail sensitive information policy validation")
    
    config = boto3.client('config')
    
    try:
        invoking_event = json.loads(event['invokingEvent'])
        account_id = event['accountId']
        result_token = event.get('resultToken', '')
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': f'Event parsing error: {str(e)}'}

    params = parse_config_parameters(event)
    if not params:
        logger.error("Failed to parse configuration parameters")
        return {'compliance_type': 'NON_COMPLIANT', 'annotation': 'Configuration parameter parsing failed'}
    
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
            if params.get('required_tags'):
                target_guardrails = filter_guardrails_by_tags(bedrock, target_guardrails, params['required_tags'])
            
            if params.get('guardrail_name'):
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
                    validation_issues = validate_sensitive_information_policy(bedrock, guardrail_id, params)
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
                        annotation = "PII detection not configured"
                    elif 'no pii entities or regex' in ' '.join(issues).lower():
                        annotation = "No PII detection configured"
                    elif 'missing pii entities' in ' '.join(issues).lower():
                        annotation = "Missing required PII entities"
                    elif 'pii entity issues' in ' '.join(issues).lower():
                        annotation = "Incorrect PII detection settings"
                    elif 'not ready' in ' '.join(issues).lower():
                        annotation = "Guardrails not ready"
                    else:
                        annotation = "PII detection configuration issues"

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