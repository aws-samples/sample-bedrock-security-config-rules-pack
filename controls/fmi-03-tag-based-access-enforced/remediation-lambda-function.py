import boto3
import json
import uuid
from datetime import datetime
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam = boto3.client('iam')

def handler(event, context):
    """
    AWS Lambda function to remediate non-compliant Bedrock tag-based access control issues.
    This function updates IAM policies to include proper tag-based conditions for Bedrock access.
    """
    logger.info("Starting remediation for Bedrock tag-based access control")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Parse event data
    try:
        # For direct Lambda invocation
        if 'entityType' in event and 'entityName' in event:
            logger.info("Parsing event data for direct Lambda invocation")
            entity_type = event['entityType']
            entity_name = event['entityName']
            
            # Handle ARN in entityName
            if entity_name.startswith('arn:aws:iam::'):
                entity_name = entity_name.split('/')[-1]
            
            required_tag_keys = event.get('requiredTagKeys', 'Environment,Project,Owner').split(',')
            required_tag_keys = [tag_key.strip() for tag_key in required_tag_keys if tag_key.strip()]
            bedrock_actions = event.get('bedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels').split(',')
            bedrock_actions = [action.strip() for action in bedrock_actions if action.strip()]
            
        # For AWS Config Remediation via SSM
        elif 'EntityName' in event:
            logger.info("Parsing event data for SSM Automation")
            entity_type = event.get('EntityType', 'role')
            entity_name = event.get('EntityName', '')
            
            # EntityName might be the full ARN from RESOURCE_ID
            if entity_name.startswith('arn:aws:iam::'):
                entity_name = entity_name.split('/')[-1]
            
            required_tag_keys = event.get('RequiredTagKeys', 'Environment,Project,Owner').split(',')
            required_tag_keys = [tag_key.strip() for tag_key in required_tag_keys if tag_key.strip()]
            bedrock_actions = event.get('BedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels').split(',')
            bedrock_actions = [action.strip() for action in bedrock_actions if action.strip()]
            
            if not entity_name:
                raise ValueError("Entity name must be provided for remediation")
                
        # For AWS Config Remediation (direct)
        elif 'configurationItem' in event:
            logger.info("Parsing event data for AWS Config Remediation")
            config_item = event['configurationItem']
            
            # Extract role name from resource ID (ARN)
            resource_id = config_item.get('resourceId', '')
            logger.info(f"Resource ID: {resource_id}")
            
            if resource_id.startswith('arn:aws:iam::'):
                # Extract role name from ARN: arn:aws:iam::account:role/path/RoleName
                entity_name = resource_id.split('/')[-1]
            else:
                # If it's already just the role name
                entity_name = resource_id
            
            # Clean the entity name to ensure it's valid
            entity_name = entity_name.strip()
            logger.info(f"Extracted entity name: '{entity_name}'")
            
            if not entity_name or '/' in entity_name or ':' in entity_name:
                raise ValueError(f"Invalid role name extracted: '{entity_name}' from resource ID: '{resource_id}'")
                
            entity_type = 'role'  # Config rule targets IAM roles
            required_tag_keys = event.get('requiredTagKeys', 'Environment,Project,Owner').split(',')
            required_tag_keys = [tag_key.strip() for tag_key in required_tag_keys if tag_key.strip()]
            bedrock_actions = event.get('bedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels').split(',')
            bedrock_actions = [action.strip() for action in bedrock_actions if action.strip()]
            
            if not entity_name:
                raise ValueError("Role name could not be extracted from resource ID")
                
        else:
            raise ValueError("Invalid event format - missing required parameters")
    
        logger.info(f"Entity type: {entity_type}")
        logger.info(f"Entity name: {entity_name}")
        logger.info(f"Required tag keys: {required_tag_keys}")
        logger.info(f"Bedrock actions: {bedrock_actions}")
        
        # Update existing policies with tag conditions
        updated_policies = []
        
        if entity_type == 'role':
            updated_policies = update_role_policies(entity_name, required_tag_keys, bedrock_actions)
            
        else:
            raise ValueError(f"Unsupported entity type: {entity_type}")
        
        if updated_policies:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Successfully updated {len(updated_policies)} policies with tag-based access control',
                    'updatedPolicies': updated_policies,
                    'entityType': entity_type,
                    'entityName': entity_name,
                    'requiredTagKeys': required_tag_keys
                })
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'No policies required updates - either no Bedrock permissions found or already compliant',
                    'entityType': entity_type,
                    'entityName': entity_name
                })
            }
            
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        logger.error(traceback.format_exc())
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Failed to apply tag-based access policy'
            })
        }

def update_role_policies(role_name, required_tag_keys, bedrock_actions):
    """Update existing role policies to add tag conditions to Bedrock statements."""
    updated_policies = []
    
    # Get inline policies
    inline_policies = iam.list_role_policies(RoleName=role_name)
    for policy_name in inline_policies['PolicyNames']:
        policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        policy_document = policy_doc['PolicyDocument']
        
        if update_policy_bedrock_statements(policy_document, required_tag_keys, bedrock_actions):
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            updated_policies.append(policy_name)
            logger.info(f"Updated inline policy: {policy_name}")
    
    # Note: Cannot modify managed policies - they're read-only
    # Log managed policies that have Bedrock permissions
    attached_policies = iam.list_attached_role_policies(RoleName=role_name)
    for policy in attached_policies['AttachedPolicies']:
        policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
        policy_version = iam.get_policy_version(
            PolicyArn=policy['PolicyArn'],
            VersionId=policy_doc['Policy']['DefaultVersionId']
        )
        if has_bedrock_permissions(policy_version['PolicyVersion']['Document'], bedrock_actions):
            logger.warning(f"Managed policy {policy['PolicyName']} has Bedrock permissions but cannot be modified")
    
    return updated_policies

def update_policy_bedrock_statements(policy_document, required_tag_keys, bedrock_actions):
    """Update Bedrock statements in a policy to add tag conditions."""
    updated = False
    
    if 'Statement' not in policy_document:
        return False
    
    tag_conditions = {}
    for tag_key in required_tag_keys:
        tag_conditions[f'aws:ResourceTag/{tag_key}'] = f'${{aws:PrincipalTag/{tag_key}}}'
    
    for statement in policy_document['Statement']:
        if (statement.get('Effect') == 'Allow' and 
            'Action' in statement):
            
            actions = statement['Action']
            if isinstance(actions, str):
                actions = [actions]
            
            # Check for Bedrock actions (specific actions, service wildcard, or full wildcard)
            has_bedrock = any(
                action in bedrock_actions or 
                action == '*' or 
                action == 'bedrock:*' or
                any(action.startswith(ba.split(':')[0] + ':') for ba in bedrock_actions if ':' in ba)
                for action in actions
            )
            
            if has_bedrock:
                # Add or update conditions
                if 'Condition' not in statement:
                    statement['Condition'] = {}
                
                if 'StringEquals' not in statement['Condition']:
                    statement['Condition']['StringEquals'] = {}
                
                # Add tag conditions
                statement['Condition']['StringEquals'].update(tag_conditions)
                updated = True
                logger.info(f"Added tag conditions to statement with actions: {actions}")
    
    return updated

def has_bedrock_permissions(policy_document, bedrock_actions):
    """Check if policy has Bedrock permissions."""
    if 'Statement' not in policy_document:
        return False
    
    for statement in policy_document['Statement']:
        if (statement.get('Effect') == 'Allow' and 'Action' in statement):
            actions = statement['Action']
            if isinstance(actions, str):
                actions = [actions]
            
            if any(
                action in bedrock_actions or 
                action == '*' or 
                action == 'bedrock:*' or
                any(action.startswith(ba.split(':')[0] + ':') for ba in bedrock_actions if ':' in ba)
                for action in actions
            ):
                return True
    
    return False