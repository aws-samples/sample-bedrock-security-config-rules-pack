import boto3
import json
import logging
import time
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def parse_parameters(event):
    """Parse parameters from event"""
    try:
        rule_parameters = event.get('configRuleParameters', {})
        
        if isinstance(rule_parameters, str):
            rule_parameters = json.loads(rule_parameters)
        
        # Either PIIEntities or RegexPattern parameters is mandatory for remediation
        pii_entities_str = rule_parameters.get('PIIEntities', '')
        
        # Collect all RegexPattern parameters dynamically
        regex_patterns = []
        for key, value in rule_parameters.items():
            if key.startswith('RegexPattern') and value and value != 'null':
                regex_patterns.append(value)
        
        if (not pii_entities_str or pii_entities_str == 'null') and not regex_patterns:
            raise ValueError("Either PIIEntities or RegexPattern parameters are required for remediation")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"SensitiveInfoGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        pii_action = rule_parameters.get('PIIAction', 'BLOCK')
        if pii_action == 'null':
            pii_action = 'BLOCK'
            
        input_action = rule_parameters.get('InputAction', pii_action)
        if input_action == 'null':
            input_action = pii_action
            
        output_action = rule_parameters.get('OutputAction', pii_action)
        if output_action == 'null':
            output_action = pii_action
        
        params = {
            'guardrail_name': guardrail_name,
            'pii_entities': pii_entities_str.split(',') if pii_entities_str and pii_entities_str != 'null' else [],
            'custom_regex_patterns': regex_patterns,
            'pii_action': pii_action,
            'input_action': input_action,
            'output_action': output_action,
            'required_tags': {}
        }
        
        # Clean up empty strings from PII entities list
        params['pii_entities'] = [entity.strip() for entity in params['pii_entities'] if entity.strip()]
        
        # Parse required tags
        required_tags_str = rule_parameters.get('RequiredTags', '')
        if required_tags_str and required_tags_str != 'null':
            for tag_pair in required_tags_str.split(','):
                if '=' in tag_pair:
                    key, value = tag_pair.split('=', 1)
                    params['required_tags'][key.strip()] = value.strip()
        
        return params
    except Exception as e:
        logger.error(f"Error parsing parameters: {str(e)}")
        return {}

def build_sensitive_information_policy_config(pii_entities, custom_regex_patterns, pii_action, input_action, output_action):
    """Build sensitive information policy configuration"""
    sensitive_info_policy_config = {}
    
    # Configure PII entities
    if pii_entities:
        pii_entities_config = []
        for entity_type in pii_entities:
            if entity_type.strip():
                entity_config = {
                    'type': entity_type.strip(),
                    'action': pii_action,
                    'inputAction': input_action,
                    'outputAction': output_action,
                    'inputEnabled': True,
                    'outputEnabled': True
                }
                pii_entities_config.append(entity_config)
        
        if pii_entities_config:
            sensitive_info_policy_config['piiEntitiesConfig'] = pii_entities_config
    
    # Configure custom regex patterns
    if custom_regex_patterns:
        regexes_config = []
        for i, pattern in enumerate(custom_regex_patterns):
            if pattern.strip():
                regex_config = {
                    'name': f"CustomPattern{i+1}",
                    'description': f"Custom regex pattern {i+1}",
                    'pattern': pattern.strip(),
                    'action': pii_action,
                    'inputAction': input_action,
                    'outputAction': output_action,
                    'inputEnabled': True,
                    'outputEnabled': True
                }
                regexes_config.append(regex_config)
        
        if regexes_config:
            sensitive_info_policy_config['regexesConfig'] = regexes_config
    
    return sensitive_info_policy_config

def find_guardrail_by_name(bedrock_client, guardrail_name):
    """Find guardrail by name and return its ID and ARN"""
    try:
        paginator = bedrock_client.get_paginator('list_guardrails')
        
        for page in paginator.paginate():
            for guardrail in page.get('guardrails', []):
                if guardrail.get('name') == guardrail_name:
                    return {
                        'id': guardrail.get('id'),
                        'arn': guardrail.get('arn'),
                        'version': guardrail.get('version', 'DRAFT')
                    }
        
        return None
    except Exception as e:
        logger.error(f"Error finding guardrail by name: {str(e)}")
        return None

def create_guardrail(bedrock_client, params):
    """Create a new guardrail"""
    sensitive_info_policy_config = build_sensitive_information_policy_config(
        params['pii_entities'],
        params['custom_regex_patterns'],
        params['pii_action'],
        params['input_action'],
        params['output_action']
    )
    
    if not sensitive_info_policy_config:
        raise ValueError('No valid sensitive information policy configuration could be built')
    
    create_params = {
        'name': params['guardrail_name'],
        'description': f"Sensitive information policy guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'sensitiveInformationPolicyConfig': sensitive_info_policy_config,
        'blockedInputMessaging': "Input blocked due to sensitive information policy violations.",
        'blockedOutputsMessaging': "Response blocked due to sensitive information policy violations.",
        'clientRequestToken': f"sensitive-info-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'SensitiveInformation'}
    ]
    
    for key, value in params['required_tags'].items():
        tags.append({'key': key, 'value': value})
    
    create_params['tags'] = tags
    
    response = bedrock_client.create_guardrail(**create_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'created'
    }

def update_guardrail(bedrock_client, guardrail_info, params):
    """Update an existing guardrail"""
    sensitive_info_policy_config = build_sensitive_information_policy_config(
        params['pii_entities'],
        params['custom_regex_patterns'],
        params['pii_action'],
        params['input_action'],
        params['output_action']
    )
    
    if not sensitive_info_policy_config:
        raise ValueError('No valid sensitive information policy configuration could be built')
    
    update_params = {
        'guardrailIdentifier': guardrail_info['id'],
        'name': params['guardrail_name'],
        'description': f"Sensitive information policy guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'sensitiveInformationPolicyConfig': sensitive_info_policy_config,
        'blockedInputMessaging': "Input blocked due to sensitive information policy violations.",
        'blockedOutputsMessaging': "Response blocked due to sensitive information policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-14: Remediation function to create or update sensitive information policy guardrail"""
    logger.info("Starting sensitive information policy guardrail remediation")
    
    try:
        params = parse_parameters(event)
        if not params:
            return {'statusCode': 400, 'error': 'Invalid parameters'}
    except ValueError as e:
        logger.error(f"Parameter validation error: {str(e)}")
        return {'statusCode': 400, 'error': str(e)}
    
    try:
        bedrock = boto3.client('bedrock')
        
        # Check if guardrail already exists
        existing_guardrail = find_guardrail_by_name(bedrock, params['guardrail_name'])
        
        if existing_guardrail:
            logger.info(f"Found existing guardrail: {existing_guardrail['id']}")
            result = update_guardrail(bedrock, existing_guardrail, params)
            logger.info(f"Updated sensitive information policy guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params)
            logger.info(f"Created sensitive information policy guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'SensitiveInformation',
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }