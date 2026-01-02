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
        
        # FilterTypes is mandatory for remediation
        filter_types_str = rule_parameters.get('FilterTypes', '')
        if not filter_types_str or filter_types_str == 'null':
            raise ValueError("FilterTypes parameter is required for remediation")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"ContextualGroundingGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        grounding_threshold = float(rule_parameters.get('GroundingThreshold', '0.75'))
        if rule_parameters.get('GroundingThreshold') == 'null':
            grounding_threshold = 0.75
            
        relevance_threshold = float(rule_parameters.get('RelevanceThreshold', '0.75'))
        if rule_parameters.get('RelevanceThreshold') == 'null':
            relevance_threshold = 0.75
            
        filter_action = rule_parameters.get('FilterAction', 'BLOCK')
        if filter_action == 'null':
            filter_action = 'BLOCK'
        
        params = {
            'guardrail_name': guardrail_name,
            'filter_types': filter_types_str.split(','),
            'grounding_threshold': grounding_threshold,
            'relevance_threshold': relevance_threshold,
            'filter_action': filter_action,
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
        
        return params
    except Exception as e:
        logger.error(f"Error parsing parameters: {str(e)}")
        return {}

def build_contextual_grounding_policy_config(filter_types, grounding_threshold, relevance_threshold, filter_action):
    """Build contextual grounding policy configuration"""
    filters_config = []
    
    for filter_type in filter_types:
        if filter_type.strip():
            # Determine threshold based on filter type
            threshold = grounding_threshold if filter_type.strip() == 'GROUNDING' else relevance_threshold
            
            filter_config = {
                'type': filter_type.strip(),
                'threshold': threshold,
                'action': filter_action,
                'enabled': True
            }
            filters_config.append(filter_config)
    
    return {'filtersConfig': filters_config} if filters_config else {}

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
    contextual_grounding_policy_config = build_contextual_grounding_policy_config(
        params['filter_types'],
        params['grounding_threshold'],
        params['relevance_threshold'],
        params['filter_action']
    )
    
    if not contextual_grounding_policy_config:
        raise ValueError('No valid contextual grounding policy configuration could be built')
    
    create_params = {
        'name': params['guardrail_name'],
        'description': f"Contextual grounding policy guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'contextualGroundingPolicyConfig': contextual_grounding_policy_config,
        'blockedInputMessaging': "Input blocked due to contextual grounding policy violations.",
        'blockedOutputsMessaging': "Response blocked due to contextual grounding policy violations.",
        'clientRequestToken': f"contextual-grounding-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'ContextualGrounding'}
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
    contextual_grounding_policy_config = build_contextual_grounding_policy_config(
        params['filter_types'],
        params['grounding_threshold'],
        params['relevance_threshold'],
        params['filter_action']
    )
    
    if not contextual_grounding_policy_config:
        raise ValueError('No valid contextual grounding policy configuration could be built')
    
    update_params = {
        'guardrailIdentifier': guardrail_info['id'],
        'name': params['guardrail_name'],
        'description': f"Contextual grounding policy guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'contextualGroundingPolicyConfig': contextual_grounding_policy_config,
        'blockedInputMessaging': "Input blocked due to contextual grounding policy violations.",
        'blockedOutputsMessaging': "Response blocked due to contextual grounding policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-15: Remediation function to create or update contextual grounding policy guardrail"""
    logger.info("Starting contextual grounding policy guardrail remediation")
    
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
            logger.info(f"Updated contextual grounding policy guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params)
            logger.info(f"Created contextual grounding policy guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'ContextualGrounding',
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }