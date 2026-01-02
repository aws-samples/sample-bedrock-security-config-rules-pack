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
        
        # ContentFilters is mandatory for remediation
        content_filters_str = rule_parameters.get('ContentFilters')
        if not content_filters_str or content_filters_str == 'null':
            raise ValueError("ContentFilters parameter is required for remediation")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"ContentFilterGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        input_strength = rule_parameters.get('InputStrength', 'MEDIUM')
        if input_strength == 'null':
            input_strength = 'MEDIUM'
            
        output_strength = rule_parameters.get('OutputStrength', 'MEDIUM')
        if output_strength == 'null':
            output_strength = 'MEDIUM'
            
        input_action = rule_parameters.get('InputAction', 'BLOCK')
        if input_action == 'null':
            input_action = 'BLOCK'
            
        output_action = rule_parameters.get('OutputAction', 'BLOCK')
        if output_action == 'null':
            output_action = 'BLOCK'
        
        params = {
            'guardrail_name': guardrail_name,
            'content_filters': content_filters_str.split(','),
            'input_strength': input_strength,
            'output_strength': output_strength,
            'input_action': input_action,
            'output_action': output_action,
            'required_tags': {}
        }
        
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

def build_content_policy_config(filters, input_strength, output_strength, input_action, output_action):
    """Build content policy configuration"""
    filters_config = []
    for filter_type in filters:
        if filter_type.strip():
            filter_config = {
                'type': filter_type.strip(),
                'inputStrength': input_strength,
                'outputStrength': output_strength,
                'inputModalities': ['TEXT'],
                'outputModalities': ['TEXT'],
                'inputAction': input_action,
                'outputAction': output_action,
                'inputEnabled': True,
                'outputEnabled': True
            }
            filters_config.append(filter_config)
    
    return {'filtersConfig': filters_config}

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
    create_params = {
        'name': params['guardrail_name'],
        'description': f"Content filter guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'contentPolicyConfig': build_content_policy_config(
            params['content_filters'],
            params['input_strength'],
            params['output_strength'],
            params['input_action'],
            params['output_action']
        ),
        'blockedInputMessaging': "Content blocked due to policy violations.",
        'blockedOutputsMessaging': "Response blocked due to content policy violations.",
        'clientRequestToken': f"content-filter-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'ContentFilter'}
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
    update_params = {
        'guardrailIdentifier': guardrail_info['id'],
        'name': params['guardrail_name'],
        'description': f"Content filter guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'contentPolicyConfig': build_content_policy_config(
            params['content_filters'],
            params['input_strength'],
            params['output_strength'],
            params['input_action'],
            params['output_action']
        ),
        'blockedInputMessaging': "Content blocked due to policy violations.",
        'blockedOutputsMessaging': "Response blocked due to content policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-12: Remediation function to create or update content filter guardrail"""
    logger.info("Starting content filter guardrail remediation")
    
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
            logger.info(f"Updated content filter guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params)
            logger.info(f"Created content filter guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'ContentFilter',
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }