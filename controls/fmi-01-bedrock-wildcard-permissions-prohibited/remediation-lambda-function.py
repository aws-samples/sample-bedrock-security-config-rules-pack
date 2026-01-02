#!/usr/bin/env python3
"""
FMI-01: Bedrock IAM Least Privilege Remediation

This Lambda function remediates IAM policies that violate least privilege principles
for Amazon Bedrock permissions by:
1. Replacing wildcard actions with specific Bedrock actions
2. Adding resource-level restrictions where applicable
3. Adding MFA conditions for administrative actions
4. Removing prohibited actions

Control ID: FMI-01
"""

import json
import boto3
import logging
import traceback
import uuid

from typing import Dict, List, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)



def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main handler function for Bedrock IAM least privilege remediation.
    
    Args:
        event: Lambda event containing remediation parameters
        context: Lambda context object
        
    Returns:
        Dict containing remediation result
    """
    logger.info("Starting remediation for Bedrock IAM least privilege")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    try:
        # Parse event data - simple format
        entity_type = event.get('entityType', 'role')
        entity_name = event.get('entityName', '')
        
        # Extract entity name from ARN if needed
        if entity_name.startswith('arn:aws:iam::'):
            entity_name = entity_name.split('/')[-1]
        
        if not entity_name:
            raise ValueError("entityName is required")
        
        # Parse configuration parameters
        remediation_actions_str = event.get('remediationActions', 'replace_wildcards,add_mfa,remove_prohibited')
        allowed_actions_str = event.get('allowedActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream,bedrock:GetFoundationModel,bedrock:ListFoundationModels')
        prohibited_actions_str = event.get('prohibitedActions', '')
        
        remediation_actions = [action.strip() for action in remediation_actions_str.split(',') if action.strip()]
        allowed_actions = [action.strip() for action in allowed_actions_str.split(',') if action.strip()]
        prohibited_actions = [action.strip() for action in prohibited_actions_str.split(',') if action.strip()]
    
        logger.info(f"Entity type: {entity_type}")
        logger.info(f"Entity name: {entity_name}")
        logger.info(f"Remediation actions: {remediation_actions}")
        logger.info(f"Allowed actions: {allowed_actions}")
        logger.info(f"Prohibited actions: {prohibited_actions}")
        
        # Initialize IAM client
        iam_client = boto3.client('iam')
        
        # Perform remediation
        remediation_result = remediate_iam_policies(
            iam_client,
            entity_type,
            entity_name,
            remediation_actions,
            allowed_actions,
            prohibited_actions
        )
        
        logger.info(f"Remediation completed: {remediation_result}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully remediated IAM least privilege violations for {entity_type} {entity_name}',
                'entityType': entity_type,
                'entityName': entity_name,
                'policiesRemediated': remediation_result.get('policiesRemediated', []),
                'remediationActions': remediation_actions,
                'changesApplied': remediation_result.get('changesApplied', [])
            })
        }
        
    except Exception as e:
        logger.error(f"Error during remediation: {str(e)}")
        logger.error(traceback.format_exc())
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'message': 'Failed to remediate IAM least privilege violations'
            })
        }


def remediate_iam_policies(
    iam_client: Any,
    entity_type: str,
    entity_name: str,
    remediation_actions: List[str],
    allowed_actions: List[str],
    prohibited_actions: List[str]
) -> Dict[str, Any]:
    """
    Remediate all IAM policies attached to an entity to follow least privilege principles.
    
    Args:
        iam_client: IAM boto3 client
        entity_type: Type of IAM entity (role, user, group)
        entity_name: Name of the IAM entity
        remediation_actions: List of remediation actions to perform
        allowed_actions: List of allowed Bedrock actions
        prohibited_actions: List of prohibited actions to remove
        
    Returns:
        Dict containing remediation results
    """
    changes_applied = []
    policies_remediated = []
    
    try:
        # Verify entity exists
        logger.info(f"Verifying entity {entity_name} exists")
        if entity_type == 'role':
            iam_client.get_role(RoleName=entity_name)
        elif entity_type == 'user':
            iam_client.get_user(UserName=entity_name)
        elif entity_type == 'group':
            iam_client.get_group(GroupName=entity_name)
        else:
            raise ValueError(f"Unsupported entity type: {entity_type}")
        
        logger.info(f"Entity {entity_name} exists, proceeding with remediation")
        
        # Get all inline policies for the entity
        inline_policies = get_inline_policies(iam_client, entity_type, entity_name)
        logger.info(f"Found {len(inline_policies)} inline policies: {list(inline_policies.keys())}")
        
        # Track if any policies have Bedrock permissions
        has_bedrock_policies = False
        
        # Remediate each inline policy
        for policy_name, policy_document in inline_policies.items():
            logger.info(f"Analyzing policy: {policy_name}")
            
            # Check if policy has Bedrock-related permissions
            if has_bedrock_permissions(policy_document):
                has_bedrock_policies = True
                logger.info(f"Policy {policy_name} contains Bedrock permissions, remediating...")
                
                # Remediate the policy
                original_policy = json.dumps(policy_document, sort_keys=True)
                remediated_policy = apply_remediation_actions(
                    policy_document,
                    remediation_actions,
                    allowed_actions,
                    prohibited_actions
                )
                
                # Check if policy was actually changed
                if json.dumps(remediated_policy, sort_keys=True) != original_policy:
                    # Apply the remediated policy
                    apply_policy_to_entity(iam_client, entity_type, entity_name, policy_name, remediated_policy)
                    
                    policies_remediated.append({
                        'policyName': policy_name,
                        'status': 'modified',
                        'policyDocument': remediated_policy
                    })
                    changes_applied.append(f"Modified policy '{policy_name}' to follow least privilege")
                    logger.info(f"Successfully remediated policy {policy_name}")
                else:
                    policies_remediated.append({
                        'policyName': policy_name,
                        'status': 'compliant',
                        'policyDocument': remediated_policy
                    })
                    changes_applied.append(f"Policy '{policy_name}' already follows least privilege principles")
                    logger.info(f"Policy {policy_name} already compliant")
            else:
                logger.info(f"Policy {policy_name} does not contain Bedrock permissions, skipping")
        
        # If no existing policies have Bedrock permissions, nothing to remediate
        if not has_bedrock_policies:
            logger.info("No existing policies contain Bedrock permissions, no remediation needed")
            changes_applied.append("No Bedrock policies found - no remediation required")
        
        return {
            'policiesRemediated': policies_remediated,
            'changesApplied': changes_applied
        }
        
    except Exception as e:
        logger.error(f"Error during policy remediation: {str(e)}")
        raise

def get_inline_policies(iam_client: Any, entity_type: str, entity_name: str) -> Dict[str, Dict[str, Any]]:
    """
    Get all inline policies for an IAM entity.
    
    Args:
        iam_client: IAM boto3 client
        entity_type: Type of IAM entity (role, user, group)
        entity_name: Name of the IAM entity
        
    Returns:
        Dict mapping policy names to policy documents
    """
    policies = {}
    
    try:
        if entity_type == 'role':
            # List all inline policies for the role
            response = iam_client.list_role_policies(RoleName=entity_name)
            policy_names = response['PolicyNames']
            
            # Get each policy document
            for policy_name in policy_names:
                policy_response = iam_client.get_role_policy(RoleName=entity_name, PolicyName=policy_name)
                policies[policy_name] = policy_response['PolicyDocument']
                
        elif entity_type == 'user':
            # List all inline policies for the user
            response = iam_client.list_user_policies(UserName=entity_name)
            policy_names = response['PolicyNames']
            
            # Get each policy document
            for policy_name in policy_names:
                policy_response = iam_client.get_user_policy(UserName=entity_name, PolicyName=policy_name)
                policies[policy_name] = policy_response['PolicyDocument']
                
        elif entity_type == 'group':
            # List all inline policies for the group
            response = iam_client.list_group_policies(GroupName=entity_name)
            policy_names = response['PolicyNames']
            
            # Get each policy document
            for policy_name in policy_names:
                policy_response = iam_client.get_group_policy(GroupName=entity_name, PolicyName=policy_name)
                policies[policy_name] = policy_response['PolicyDocument']
                
    except Exception as e:
        logger.error(f"Error getting inline policies for {entity_type} {entity_name}: {str(e)}")
        raise
    
    return policies

def has_bedrock_permissions(policy_document: Dict[str, Any]) -> bool:
    """
    Check if a policy document contains Bedrock-related permissions.
    
    Args:
        policy_document: IAM policy document
        
    Returns:
        True if policy contains Bedrock permissions, False otherwise
    """
    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue
            
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Check for Bedrock actions or wildcards that could include Bedrock
        for action in actions:
            if action.startswith('bedrock:') or action == '*':
                return True
    
    return False

def apply_policy_to_entity(
    iam_client: Any,
    entity_type: str,
    entity_name: str,
    policy_name: str,
    policy_document: Dict[str, Any]
) -> None:
    """
    Apply a policy document to an IAM entity.
    
    Args:
        iam_client: IAM boto3 client
        entity_type: Type of IAM entity (role, user, group)
        entity_name: Name of the IAM entity
        policy_name: Name of the policy
        policy_document: Policy document to apply
    """
    policy_json = json.dumps(policy_document)
    
    if entity_type == 'role':
        iam_client.put_role_policy(
            RoleName=entity_name,
            PolicyName=policy_name,
            PolicyDocument=policy_json
        )
    elif entity_type == 'user':
        iam_client.put_user_policy(
            UserName=entity_name,
            PolicyName=policy_name,
            PolicyDocument=policy_json
        )
    elif entity_type == 'group':
        iam_client.put_group_policy(
            GroupName=entity_name,
            PolicyName=policy_name,
            PolicyDocument=policy_json
        )

def create_least_privilege_policy(allowed_actions: List[str]) -> Dict[str, Any]:
    """
    Create a new least privilege policy for Bedrock.
    
    Args:
        allowed_actions: List of allowed Bedrock actions
        
    Returns:
        Policy document dict
    """
    # Administrative actions that require MFA
    admin_actions = [
        'bedrock:PutModelInvocationLoggingConfiguration',
        'bedrock:DeleteCustomModel',
        'bedrock:StopModelCustomizationJob'
    ]
    
    # Separate admin actions from regular actions
    regular_actions = [action for action in allowed_actions if action not in admin_actions]
    admin_actions_allowed = [action for action in allowed_actions if action in admin_actions]
    
    statements = []
    
    # Regular actions statement
    if regular_actions:
        statements.append({
            "Sid": "BedrockLeastPrivilegeAccess",
            "Effect": "Allow",
            "Action": regular_actions,
            "Resource": "*"
        })
    
    # Administrative actions with MFA requirement
    if admin_actions_allowed:
        statements.append({
            "Sid": "BedrockAdminActionsWithMFA",
            "Effect": "Allow",
            "Action": admin_actions_allowed,
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                },
                "NumericLessThan": {
                    "aws:MultiFactorAuthAge": "3600"
                }
            }
        })
    
    return {
        "Version": "2012-10-17",
        "Statement": statements
    }

def apply_remediation_actions(
    policy_document: Dict[str, Any],
    remediation_actions: List[str],
    allowed_actions: List[str],
    prohibited_actions: List[str]
) -> Dict[str, Any]:
    """
    Apply remediation actions to an existing policy document.
    
    Args:
        policy_document: Original policy document
        remediation_actions: List of remediation actions to perform
        allowed_actions: List of allowed Bedrock actions
        prohibited_actions: List of prohibited actions to remove
        
    Returns:
        Remediated policy document
    """
    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements]
    
    remediated_statements = []
    
    for statement in statements:
        if statement.get('Effect') != 'Allow':
            remediated_statements.append(statement)
            continue
        
        actions = statement.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        # Check if this statement has Bedrock actions
        bedrock_actions = [action for action in actions if action.startswith('bedrock:') or action == '*']
        
        if not bedrock_actions:
            remediated_statements.append(statement)
            continue
        
        # Apply remediation actions
        new_statement = statement.copy()
        
        if 'replace_wildcards' in remediation_actions:
            new_statement = replace_wildcard_actions(new_statement, allowed_actions)
        
        if 'remove_prohibited' in remediation_actions:
            new_statement = remove_prohibited_actions(new_statement, prohibited_actions)
        
        if 'add_mfa' in remediation_actions:
            new_statement = add_mfa_conditions(new_statement)
        
        if 'add_resource_restrictions' in remediation_actions:
            new_statement = add_resource_restrictions(new_statement)
        
        remediated_statements.append(new_statement)
    
    return {
        "Version": policy_document.get("Version", "2012-10-17"),
        "Statement": remediated_statements
    }

def replace_wildcard_actions(statement: Dict[str, Any], allowed_actions: List[str]) -> Dict[str, Any]:
    """Replace wildcard actions with specific allowed actions."""
    actions = statement.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    new_actions = []
    for action in actions:
        if action == '*' or action == 'bedrock:*':
            new_actions.extend(allowed_actions)
        else:
            new_actions.append(action)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_actions = []
    for action in new_actions:
        if action not in seen:
            seen.add(action)
            unique_actions.append(action)
    
    new_statement = statement.copy()
    new_statement['Action'] = unique_actions
    return new_statement

def remove_prohibited_actions(statement: Dict[str, Any], prohibited_actions: List[str]) -> Dict[str, Any]:
    """Remove prohibited actions from the statement."""
    actions = statement.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    filtered_actions = [action for action in actions if action not in prohibited_actions]
    
    new_statement = statement.copy()
    new_statement['Action'] = filtered_actions
    return new_statement

def add_mfa_conditions(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Add MFA conditions for administrative actions."""
    actions = statement.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    admin_actions = [
        'bedrock:PutModelInvocationLoggingConfiguration',
        'bedrock:DeleteCustomModel',
        'bedrock:StopModelCustomizationJob'
    ]
    
    has_admin_actions = any(action in admin_actions for action in actions)
    
    if has_admin_actions:
        new_statement = statement.copy()
        conditions = new_statement.get('Condition', {})
        
        # Add MFA conditions
        if 'Bool' not in conditions:
            conditions['Bool'] = {}
        conditions['Bool']['aws:MultiFactorAuthPresent'] = 'true'
        
        if 'NumericLessThan' not in conditions:
            conditions['NumericLessThan'] = {}
        conditions['NumericLessThan']['aws:MultiFactorAuthAge'] = '3600'
        
        new_statement['Condition'] = conditions
        return new_statement
    
    return statement

def add_resource_restrictions(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Add resource-level restrictions where applicable."""
    # For Bedrock, most actions require wildcard resources
    # This is a placeholder for future enhancements when Bedrock supports resource-level permissions
    return statement

if __name__ == "__main__":
    # Test event for local testing
    test_event = {
        'entityType': 'role',
        'entityName': 'TestBedrockRole',
        'remediationActions': 'replace_wildcards,add_mfa,remove_prohibited',
        'allowedActions': 'bedrock:InvokeModel,bedrock:GetFoundationModel,bedrock:ListFoundationModels',
        'prohibitedActions': 'bedrock:DeleteCustomModel'
    }
    
    # Mock context
    class MockContext:
        def __init__(self):
            self.function_name = "test-function"
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
        
        def get_remaining_time_in_millis(self):
            return 30000
    
    result = handler(test_event, MockContext())
    print(json.dumps(result, indent=2))
