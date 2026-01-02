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
        
        # Either BlockedWords or ManagedWordLists is mandatory for remediation
        blocked_words_str = rule_parameters.get('BlockedWords', '')
        managed_word_lists_str = rule_parameters.get('ManagedWordLists', '')
        
        if (not blocked_words_str or blocked_words_str == 'null') and (not managed_word_lists_str or managed_word_lists_str == 'null'):
            raise ValueError("Either BlockedWords or ManagedWordLists parameter is required for remediation")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"WordPolicyGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        input_action = rule_parameters.get('InputAction', 'BLOCK')
        if input_action == 'null':
            input_action = 'BLOCK'
            
        output_action = rule_parameters.get('OutputAction', 'BLOCK')
        if output_action == 'null':
            output_action = 'BLOCK'
        
        params = {
            'guardrail_name': guardrail_name,
            'blocked_words': blocked_words_str.split(',') if blocked_words_str and blocked_words_str != 'null' else [],
            'managed_word_lists': managed_word_lists_str.split(',') if managed_word_lists_str and managed_word_lists_str != 'null' else [],
            'input_action': input_action,
            'output_action': output_action,
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
        
        return params
    except Exception as e:
        logger.error(f"Error parsing parameters: {str(e)}")
        return {}

def build_word_policy_config(blocked_words, managed_word_lists, input_action, output_action):
    """Build word policy configuration"""
    word_policy_config = {}
    
    # Configure blocked words
    if blocked_words:
        words_config = []
        for word in blocked_words:
            if word.strip():
                word_config = {
                    'text': word.strip(),
                    'inputAction': input_action,
                    'outputAction': output_action,
                    'inputEnabled': True,
                    'outputEnabled': True
                }
                words_config.append(word_config)
        
        if words_config:
            word_policy_config['wordsConfig'] = words_config
    
    # Configure managed word lists
    if managed_word_lists:
        managed_word_lists_config = []
        for word_list_type in managed_word_lists:
            if word_list_type.strip():
                list_config = {
                    'type': word_list_type.strip(),
                    'inputAction': input_action,
                    'outputAction': output_action,
                    'inputEnabled': True,
                    'outputEnabled': True
                }
                managed_word_lists_config.append(list_config)
        
        if managed_word_lists_config:
            word_policy_config['managedWordListsConfig'] = managed_word_lists_config
    
    return word_policy_config

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
    word_policy_config = build_word_policy_config(
        params['blocked_words'],
        params['managed_word_lists'],
        params['input_action'],
        params['output_action']
    )
    
    if not word_policy_config:
        raise ValueError('No valid word policy configuration could be built')
    
    create_params = {
        'name': params['guardrail_name'],
        'description': f"Word policy guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'wordPolicyConfig': word_policy_config,
        'blockedInputMessaging': "Input blocked due to word policy violations.",
        'blockedOutputsMessaging': "Response blocked due to word policy violations.",
        'clientRequestToken': f"word-policy-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'WordPolicy'}
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
    word_policy_config = build_word_policy_config(
        params['blocked_words'],
        params['managed_word_lists'],
        params['input_action'],
        params['output_action']
    )
    
    if not word_policy_config:
        raise ValueError('No valid word policy configuration could be built')
    
    update_params = {
        'guardrailIdentifier': guardrail_info['id'],
        'name': params['guardrail_name'],
        'description': f"Word policy guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'wordPolicyConfig': word_policy_config,
        'blockedInputMessaging': "Input blocked due to word policy violations.",
        'blockedOutputsMessaging': "Response blocked due to word policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-13: Remediation function to create or update word policy guardrail"""
    logger.info("Starting word policy guardrail remediation")
    
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
            logger.info(f"Updated word policy guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params)
            logger.info(f"Created word policy guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'WordPolicy',
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }