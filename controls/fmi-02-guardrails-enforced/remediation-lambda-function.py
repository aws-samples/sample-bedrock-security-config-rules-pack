import boto3
import json
import uuid
from datetime import datetime
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    AWS Lambda function to remediate non-compliant Bedrock guardrails SCP issues.
    This function creates or updates an SCP to mandate the use of guardrails for
    Bedrock model invocations.
    """
    logger.info("Starting remediation for Bedrock guardrails SCP")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Parse event data
    try:
        # For direct Lambda invocation
        if 'requiredGuardrailArns' in event:
            logger.info("Parsing event data for direct Lambda invocation")
            required_guardrail_arns = []
            if event['requiredGuardrailArns'] and event['requiredGuardrailArns'] != 'none':
                required_guardrail_arns = event['requiredGuardrailArns'].split(',')
                required_guardrail_arns = [arn.strip() for arn in required_guardrail_arns if arn.strip()]
            
            # Get configurable parameters
            allowed_bedrock_actions_param = event.get('allowedBedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream')
            allowed_bedrock_actions = [action.strip() for action in allowed_bedrock_actions_param.split(',') if action.strip()]
            guardrail_condition_key = event.get('guardrailConditionKey', 'bedrock:guardrailIdentifier')
            
            target_ou_id = event.get('targetOuId', 'root')
            policy_name = event.get('policyName', f'BedrockGuardrailsRequirement-{uuid.uuid4().hex[:8]}')
            
        # For AWS Config Remediation
        elif 'invokingEvent' in event:
            logger.info("Parsing event data for AWS Config Remediation")
            rule_parameters = json.loads(event['ruleParameters']) if 'ruleParameters' in event else {}
            required_guardrail_arns = []
            guardrail_arns_param = rule_parameters.get('requiredGuardrailArns', '')
            if guardrail_arns_param and guardrail_arns_param != 'none':
                required_guardrail_arns = guardrail_arns_param.split(',')
                required_guardrail_arns = [arn.strip() for arn in required_guardrail_arns if arn.strip()]
            
            # Get configurable parameters
            allowed_bedrock_actions_param = rule_parameters.get('allowedBedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream')
            allowed_bedrock_actions = [action.strip() for action in allowed_bedrock_actions_param.split(',') if action.strip()]
            guardrail_condition_key = rule_parameters.get('guardrailConditionKey', 'bedrock:guardrailIdentifier')
            
            target_ou_id = rule_parameters.get('targetOuId', 'root')
            policy_name = rule_parameters.get('policyName', f'BedrockGuardrailsRequirement-{uuid.uuid4().hex[:8]}')
            
        else:
            # Default values if not provided
            logger.info("No event data provided, using default values")
            required_guardrail_arns = []
            allowed_bedrock_actions = ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream']
            guardrail_condition_key = 'bedrock:guardrailIdentifier'
            target_ou_id = 'root'
            policy_name = f'BedrockGuardrailsRequirement-{uuid.uuid4().hex[:8]}'
    
        logger.info(f"Required guardrail ARNs: {required_guardrail_arns}")
        logger.info(f"Target OU ID: {target_ou_id}")
        logger.info(f"Policy name: {policy_name}")
        
        # Initialize Organizations client
        try:
            org_client = boto3.client('organizations')
            logger.info("Successfully initialized AWS Organizations client")
        except Exception as e:
            logger.error(f"Failed to initialize AWS Organizations client: {str(e)}")
            raise Exception(f"Failed to initialize AWS Organizations client: {str(e)}")
        
        # Get organization root ID if target is 'root'
        if target_ou_id == 'root':
            try:
                roots_response = org_client.list_roots()
                roots = roots_response.get('Roots', [])
                if not roots:
                    raise Exception("No organization root found in AWS Organizations")
                target_ou_id = roots[0]['Id']
                logger.info(f"Using organization root ID: {target_ou_id}")
                
                # Validate the root ID format
                if not target_ou_id.startswith('r-'):
                    raise Exception(f"Invalid organization root ID format: {target_ou_id}. Expected format: r-xxxxxxxxxx")
                    
            except Exception as e:
                logger.error(f"Failed to get organization root: {str(e)}")
                raise Exception(f"Failed to get organization root: {str(e)}")
        
        # Check if a suitable SCP already exists
        existing_policy_id = find_existing_guardrails_scp(org_client, policy_name)
        
        # Create or update the SCP
        if existing_policy_id:
            logger.info(f"Updating existing SCP: {existing_policy_id}")
            policy_id = update_guardrails_scp(org_client, existing_policy_id, required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key)
        else:
            logger.info(f"Creating new SCP: {policy_name}")
            policy_id = create_guardrails_scp(org_client, policy_name, required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key)
            logger.info(f"Created new SCP: {policy_id}")
        
        # Attach the policy to the target OU if not already attached
        attach_policy_if_needed(org_client, policy_id, target_ou_id)
        
        return {
            'statusCode': 200,
            'message': f"Successfully remediated Bedrock guardrails SCP with policy ID: {policy_id}",
            'policyId': policy_id
        }
        
    except ValueError as ve:
        logger.error(f"Validation error in Bedrock guardrails SCP remediation: {str(ve)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 400,
            'message': f"Validation error: {str(ve)}",
            'errorType': 'ValidationError'
        }
    except boto3.exceptions.Boto3Error as be:
        logger.error(f"AWS API error in Bedrock guardrails SCP remediation: {str(be)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'message': f"AWS API error: {str(be)}",
            'errorType': 'AWSError'
        }
    except Exception as e:
        logger.error(f"Unexpected error in Bedrock guardrails SCP remediation: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'message': f"Unexpected error: {str(e)}",
            'errorType': type(e).__name__
        }

def find_existing_guardrails_scp(org_client, policy_name):
    """
    Find an existing SCP with the given name.
    """
    try:
        paginator = org_client.get_paginator('list_policies')
        for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
            for policy in page['Policies']:
                if policy['Name'] == policy_name:
                    return policy['Id']
        return None
    except Exception as e:
        logger.error(f"Error finding existing SCP: {str(e)}")
        logger.error(traceback.format_exc())
        return None

def create_guardrails_scp(org_client, policy_name, required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key):
    """
    Create a new SCP to mandate guardrails for Bedrock model invocations.
    """
    # Create policy content based on required guardrail ARNs
    policy_content = create_policy_content(required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key)
    
    # Create the policy
    response = org_client.create_policy(
        Content=json.dumps(policy_content),
        Description=f"Mandates the use of guardrails for Amazon Bedrock model invocations. Created by automated remediation on {datetime.now().strftime('%Y-%m-%d')}",
        Name=policy_name,
        Type='SERVICE_CONTROL_POLICY'
    )
    
    return response['Policy']['PolicySummary']['Id']

def update_guardrails_scp(org_client, policy_id, required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key):
    """
    Update an existing SCP with new Bedrock guardrails requirements.
    """
    # Create policy content based on required guardrail ARNs
    policy_content = create_policy_content(required_guardrail_arns, allowed_bedrock_actions, guardrail_condition_key)
    
    # Update the policy
    org_client.update_policy(
        PolicyId=policy_id,
        Content=json.dumps(policy_content),
        Description=f"Mandates the use of guardrails for Amazon Bedrock model invocations. Updated by automated remediation on {datetime.now().strftime('%Y-%m-%d')}"
    )
    
    return policy_id

def create_policy_content(required_guardrail_arns, allowed_bedrock_actions=None, guardrail_condition_key=None):
    """
    Create the SCP policy content based on required guardrail ARNs and configurable parameters.
    """
    # Set defaults if not provided
    if allowed_bedrock_actions is None:
        allowed_bedrock_actions = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    if guardrail_condition_key is None:
        guardrail_condition_key = "bedrock:guardrailIdentifier"
    if required_guardrail_arns:
        # Create policy that requires specific guardrails
        policy_content = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireSpecificGuardrailsForBedrockInvocation",
                    "Effect": "Deny",
                    "Action": allowed_bedrock_actions,
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            guardrail_condition_key: required_guardrail_arns
                        }
                    }
                }
            ]
        }
    else:
        # Create policy that requires any guardrail (doesn't specify which one)
        policy_content = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RequireAnyGuardrailForBedrockInvocation",
                    "Effect": "Deny",
                    "Action": allowed_bedrock_actions,
                    "Resource": "*",
                    "Condition": {
                        "Null": {
                            guardrail_condition_key: "true"
                        }
                    }
                }
            ]
        }
    
    return policy_content

def attach_policy_if_needed(org_client, policy_id, target_id):
    """
    Attach the policy to the target OU if not already attached.
    """
    try:
        # Validate target_id format
        if not target_id or not isinstance(target_id, str):
            raise ValueError(f"Invalid target_id: {target_id}. Must be a non-empty string.")
        
        # AWS Organizations target IDs should start with 'r-' (root) or 'ou-' (organizational unit)
        if not (target_id.startswith('r-') or target_id.startswith('ou-')):
            raise ValueError(f"Invalid target_id format: {target_id}. Must start with 'r-' (root) or 'ou-' (organizational unit).")
        
        logger.info(f"Checking if policy {policy_id} is already attached to target {target_id}")
        
        # Check if policy is already attached
        attached_policies = []
        paginator = org_client.get_paginator('list_policies_for_target')

        for page in paginator.paginate(TargetId=target_id, Filter='SERVICE_CONTROL_POLICY'):
            attached_policies.extend(page['Policies'])
        
        already_attached = any(policy['Id'] == policy_id for policy in attached_policies)
        if not already_attached:
            logger.info(f"Attaching policy {policy_id} to target {target_id}")
            org_client.attach_policy(
                PolicyId=policy_id,
                TargetId=target_id
            )
            logger.info(f"Successfully attached policy {policy_id} to target {target_id}")
        else:
            logger.info(f"Policy {policy_id} is already attached to target {target_id}")
            
    except ValueError as ve:
        logger.error(f"Validation error for target_id: {str(ve)}")
        logger.error(traceback.format_exc())
        raise
    except Exception as e:
        logger.error(f"Error attaching policy to target {target_id}: {str(e)}")
        logger.error(traceback.format_exc())
        raise