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
        
        # TopicFilters is mandatory for remediation
        topic_filters_str = rule_parameters.get('TopicFilters')
        if not topic_filters_str or topic_filters_str == 'null':
            raise ValueError("TopicFilters parameter is required for remediation")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"TopicFilterGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        input_action = rule_parameters.get('InputAction', 'BLOCK')
        if input_action == 'null':
            input_action = 'BLOCK'
            
        output_action = rule_parameters.get('OutputAction', 'BLOCK')
        if output_action == 'null':
            output_action = 'BLOCK'
            
        example = rule_parameters.get('Example')
        if example == 'null':
            example = None
        
        params = {
            'guardrail_name': guardrail_name,
            'topic_filters': topic_filters_str.split(','),
            'topic_filter_action': rule_parameters.get('TopicFilterAction', 'DENY'),
            'input_action': input_action,
            'output_action': output_action,
            'example': example,
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

def build_topic_policy_config(topics, action, input_action=None, output_action=None, example=None):
    """Build topic policy configuration"""
    topics_config = []
    for topic in topics:
        if topic.strip():
            topic_config = {
                'name': topic.strip(),
                'definition': f"Filter for {topic.strip()} content",
                'type': action,
                'inputEnabled': True,
                'outputEnabled': True
            }
            
            # Add input/output actions if specified
            if input_action:
                topic_config['inputAction'] = input_action
            if output_action:
                topic_config['outputAction'] = output_action
            
            # Add example if specified
            if example:
                topic_config['examples'] = [example]
            
            topics_config.append(topic_config)
    
    return {'topicsConfig': topics_config}

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
        'description': f"Topic filter guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'topicPolicyConfig': build_topic_policy_config(
            params['topic_filters'], 
            params['topic_filter_action'],
            params['input_action'],
            params['output_action'],
            params['example']
        ),
        'blockedInputMessaging': "Topic blocked due to policy violations.",
        'blockedOutputsMessaging': "Response blocked due to topic policy violations.",
        'clientRequestToken': f"topic-filter-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'TopicFilter'}
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
        'description': f"Topic filter guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'topicPolicyConfig': build_topic_policy_config(
            params['topic_filters'], 
            params['topic_filter_action'],
            params['input_action'],
            params['output_action'],
            params['example']
        ),
        'blockedInputMessaging': "Topic blocked due to policy violations.",
        'blockedOutputsMessaging': "Response blocked due to topic policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-11: Remediation function to create or update topic filter guardrail"""
    logger.info("Starting topic filter guardrail remediation")
    
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
            logger.info(f"Updated topic filter guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params)
            logger.info(f"Created topic filter guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'TopicFilter',
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }