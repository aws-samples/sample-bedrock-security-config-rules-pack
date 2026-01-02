import boto3
import json
import logging
import time
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_guardrail_profile_for_region(region):
    """Map AWS region to appropriate guardrail profile identifier"""
    # US regions
    us_regions = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
    ]
    
    # GovCloud regions
    govcloud_regions = [
        'us-gov-east-1', 'us-gov-west-1'
    ]
    
    # EU regions
    eu_regions = [
        'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 
        'eu-north-1', 'eu-south-1', 'eu-south-2', 'eu-central-2'
    ]
    
    # APAC regions
    apac_regions = [
        'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
        'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-4',
        'ap-south-1', 'ap-south-2', 'ap-east-1'
    ]
    
    if region in us_regions:
        return 'us.guardrail.v1:0'
    elif region in govcloud_regions:
        return 'us-gov.guardrail.v1:0'
    elif region in eu_regions:
        return 'eu.guardrail.v1:0'
    elif region in apac_regions:
        return 'apac.guardrail.v1:0'
    else:
        # Default to US profile for unknown regions
        logger.warning(f"Unknown region {region}, defaulting to US guardrail profile")
        return 'us.guardrail.v1:0'

def parse_parameters(event):
    """Parse parameters from event"""
    try:
        rule_parameters = event.get('configRuleParameters', {})
        
        if isinstance(rule_parameters, str):
            rule_parameters = json.loads(rule_parameters)
        
        # AutomatedReasoningPolicies parameter handling
        automated_reasoning_policies_str = rule_parameters.get('AutomatedReasoningPolicies', '')
        if not automated_reasoning_policies_str or automated_reasoning_policies_str == 'null':
            # No policies provided - will be handled later in get_or_create_policies
            automated_reasoning_policies_str = ''
            logger.info("No automated reasoning policies specified")
        
        guardrail_name = rule_parameters.get('GuardrailName')
        if not guardrail_name or guardrail_name == 'null':
            guardrail_name = f"AutomatedReasoningGuardrail-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        min_confidence_threshold = float(rule_parameters.get('MinConfidenceThreshold', '0.8'))
        if rule_parameters.get('MinConfidenceThreshold') == 'null':
            min_confidence_threshold = 0.8
        
        params = {
            'guardrail_name': guardrail_name,
            'automated_reasoning_policies': automated_reasoning_policies_str.split(','),
            'min_confidence_threshold': min_confidence_threshold,
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
        
        return params
    except Exception as e:
        logger.error(f"Error parsing parameters: {str(e)}")
        return {}

def build_automated_reasoning_policy_config(automated_reasoning_policies, min_confidence_threshold):
    """Build automated reasoning policy configuration"""
    # If no policies provided, create a sample policy for demonstration
    if not automated_reasoning_policies or len(automated_reasoning_policies) == 0:
        logger.warning("No automated reasoning policies provided, creating sample policy")
        # Generate a sample 12-character rule ID
        sample_rule_id = f"A{int(time.time()) % 99999999999:011d}"
        automated_reasoning_policies = [f"arn:aws:bedrock:{boto3.Session().region_name}:{boto3.client('sts').get_caller_identity()['Account']}:automated-reasoning-policy/{sample_rule_id}"]
        logger.info(f"Created sample policy ARN: {automated_reasoning_policies[0]}")
    
    # Note: In a real implementation, you would need to validate that the policy ARNs exist
    # This is a simplified example that uses the provided policy identifiers
    automated_reasoning_policy_config = {
        'policies': automated_reasoning_policies,
        'confidenceThreshold': min_confidence_threshold
    }
    
    return automated_reasoning_policy_config

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

def create_guardrail(bedrock_client, params, region):
    """Create a new guardrail"""
    automated_reasoning_policy_config = build_automated_reasoning_policy_config(
        params['automated_reasoning_policies'],
        params['min_confidence_threshold']
    )
    
    if not automated_reasoning_policy_config:
        raise ValueError('No valid automated reasoning policy configuration could be built')
    
    create_params = {
        'name': params['guardrail_name'],
        'description': f"Automated reasoning policy guardrail created by AWS Config remediation - {datetime.now().isoformat()}",
        'automatedReasoningPolicyConfig': automated_reasoning_policy_config,
        'crossRegionConfig': {
            'guardrailProfileIdentifier': get_guardrail_profile_for_region(region)
        },
        'blockedInputMessaging': "Input blocked due to automated reasoning policy violations.",
        'blockedOutputsMessaging': "Response blocked due to automated reasoning policy violations.",
        'clientRequestToken': f"automated-reasoning-{int(time.time())}"
    }
    
    # Add tags
    tags = [
        {'key': 'CreatedBy', 'value': 'AWSConfigRemediation'},
        {'key': 'SafeguardType', 'value': 'AutomatedReasoning'}
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

def update_guardrail(bedrock_client, guardrail_info, params, region):
    """Update an existing guardrail"""
    automated_reasoning_policy_config = build_automated_reasoning_policy_config(
        params['automated_reasoning_policies'],
        params['min_confidence_threshold']
    )
    
    if not automated_reasoning_policy_config:
        raise ValueError('No valid automated reasoning policy configuration could be built')
    
    update_params = {
        'guardrailIdentifier': guardrail_info['id'],
        'name': params['guardrail_name'],
        'description': f"Automated reasoning policy guardrail updated by AWS Config remediation - {datetime.now().isoformat()}",
        'automatedReasoningPolicyConfig': automated_reasoning_policy_config,
        'crossRegionConfig': {
            'guardrailProfileIdentifier': get_guardrail_profile_for_region(region)
        },
        'blockedInputMessaging': "Input blocked due to automated reasoning policy violations.",
        'blockedOutputsMessaging': "Response blocked due to automated reasoning policy violations."
    }
    
    response = bedrock_client.update_guardrail(**update_params)
    
    return {
        'guardrailId': response.get('guardrailId'),
        'guardrailArn': response.get('guardrailArn'),
        'action': 'updated'
    }

def handler(event, context):
    """FMI-16: Remediation function to create or update automated reasoning policy guardrail"""
    logger.info("Starting automated reasoning policy guardrail remediation")
    
    try:
        params = parse_parameters(event)
        if not params:
            return {'statusCode': 400, 'error': 'Invalid parameters'}
    except ValueError as e:
        logger.error(f"Parameter validation error: {str(e)}")
        return {'statusCode': 400, 'error': str(e)}
    
    try:
        bedrock = boto3.client('bedrock')
        region = boto3.Session().region_name
        logger.info(f"Operating in region: {region}")
        
        # Check if guardrail already exists
        existing_guardrail = find_guardrail_by_name(bedrock, params['guardrail_name'])
        
        if existing_guardrail:
            logger.info(f"Found existing guardrail: {existing_guardrail['id']}")
            result = update_guardrail(bedrock, existing_guardrail, params, region)
            logger.info(f"Updated automated reasoning policy guardrail: {result['guardrailId']}")
        else:
            logger.info(f"No existing guardrail found, creating new one: {params['guardrail_name']}")
            result = create_guardrail(bedrock, params, region)
            logger.info(f"Created automated reasoning policy guardrail: {result['guardrailId']}")
        
        return {
            'statusCode': 200,
            'guardrailId': result['guardrailId'],
            'guardrailArn': result['guardrailArn'],
            'guardrailName': params['guardrail_name'],
            'safeguardType': 'AutomatedReasoning',
            'region': region,
            'guardrailProfile': get_guardrail_profile_for_region(region),
            'action': result['action']
        }

    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'error': f"Remediation failed: {str(e)}"
        }