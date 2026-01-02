#!/usr/bin/env python3
"""
FMI-2: Bedrock IAM Least Privilege Check

This AWS Config rule checks if IAM policies granting Amazon Bedrock permissions 
follow the principle of least privilege by:
1. Avoiding wildcard permissions (bedrock:*)
2. Using specific actions instead of broad permissions
3. Implementing proper resource restrictions where applicable
4. Checking for overly permissive conditions

Control ID: FMI-2
Compliance: NON_COMPLIANT if policies grant excessive Bedrock permissions
"""

import json
import boto3
import logging
import traceback
from typing import Dict, List, Any, Set
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS Config client
config = boto3.client('config')

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main handler function for the Bedrock IAM Least Privilege check.
    
    Args:
        event: AWS Config rule event
        context: Lambda context object
        
    Returns:
        Dict containing compliance evaluation result
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    try:
        # Parse the event
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        configuration_item = invoking_event.get('configurationItem', {})
        
        # Get result token
        result_token = event.get('resultToken')
        logger.info(f"Result token available: {bool(result_token)}")
        
        # Get configuration parameters
        max_wildcard_actions = int(rule_parameters.get('maxWildcardActions', '0'))
        allowed_wildcard_actions = rule_parameters.get('allowedWildcardActions', '').split(',')
        allowed_wildcard_actions = [action.strip() for action in allowed_wildcard_actions if action.strip()]
        
        prohibited_actions = rule_parameters.get('prohibitedActions', '').split(',')
        prohibited_actions = [action.strip() for action in prohibited_actions if action.strip()]
        
        require_resource_restrictions = rule_parameters.get('requireResourceRestrictions', 'false').lower() == 'true'
        
        # Filter options
        role_path_filter = rule_parameters.get('rolePathFilter', '').strip() or None
        role_tag_filter = rule_parameters.get('roleTagFilter', '').strip() or None
        
        logger.info(f"Max wildcard actions allowed: {max_wildcard_actions}")
        logger.info(f"Allowed wildcard actions: {allowed_wildcard_actions}")
        logger.info(f"Prohibited actions: {prohibited_actions}")
        logger.info(f"Require resource restrictions: {require_resource_restrictions}")
        logger.info(f"Role path filter: {role_path_filter}")
        logger.info(f"Role tag filter: {role_tag_filter}")
        
        # Handle different invocation types
        logger.info(f"Configuration item present: {bool(configuration_item)}")
        if configuration_item:
            logger.info(f"Configuration item resource type: {configuration_item.get('resourceType')}")
        
        if configuration_item and configuration_item.get('resourceType') == 'AWS::IAM::Role':
            # Configuration change triggered for a specific role
            logger.info("Processing single role configuration change")
            evaluations = [evaluate_role(configuration_item, max_wildcard_actions, allowed_wildcard_actions, 
                                        prohibited_actions, require_resource_restrictions, role_path_filter, role_tag_filter)]
        else:
            # Periodic evaluation - check all roles
            logger.info("Processing periodic evaluation - checking all roles")
            evaluations = evaluate_all_roles(max_wildcard_actions, allowed_wildcard_actions, 
                                           prohibited_actions, require_resource_restrictions,
                                           role_path_filter, role_tag_filter)
        
        logger.info(f"Generated {len(evaluations)} evaluations")
        for i, evaluation in enumerate(evaluations):
            logger.info(f"Evaluation {i+1}: {evaluation['ComplianceResourceId']} = {evaluation['ComplianceType']}")
        
        # Submit evaluations in batches of 100 (AWS Config limit)
        if evaluations:
            if result_token:
                # Process evaluations in batches of 100
                batch_size = 100
                for i in range(0, len(evaluations), batch_size):
                    batch = evaluations[i:i + batch_size]
                    logger.info(f"Submitting batch of {len(batch)} evaluations")
                    config.put_evaluations(
                        Evaluations=batch,
                        ResultToken=result_token
                    )
            else:
                logger.info("No result token provided - evaluations generated but not submitted to Config")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'evaluationsCount': len(evaluations)
            })
        }
        
    except Exception as e:
        error_message = f"Error evaluating Bedrock IAM least privilege: {str(e)}"
        logger.error(error_message)
        logger.error(traceback.format_exc())
        
        # Submit error evaluation if result token is available
        if 'resultToken' in event and event['resultToken']:
            try:
                evaluation = {
                    'ComplianceResourceType': 'AWS::::Account',
                    'ComplianceResourceId': event.get('accountId', 'unknown'),
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': error_message[:256],
                    'OrderingTimestamp': datetime.utcnow()
                }
                
                config.put_evaluations(
                    Evaluations=[evaluation],
                    ResultToken=event['resultToken']
                )
            except Exception as eval_error:
                logger.error(f"Failed to submit evaluation: {str(eval_error)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'complianceType': 'NON_COMPLIANT',
                'annotation': error_message
            })
        }

def evaluate_all_roles(max_wildcard_actions, allowed_wildcard_actions, prohibited_actions, require_resource_restrictions, role_path_filter=None, role_tag_filter=None):
    """Evaluate all IAM roles for compliance."""
    evaluations = []
    iam_client = boto3.client('iam')
    
    try:
        # Define path prefixes to exclude AWS managed roles
        aws_managed_paths = ['/aws-service-role/', '/service-role/']
        
        # Get roles with path filter
        roles_paginator = iam_client.get_paginator('list_roles')
        pagination_config = {}
        
        # Apply custom path filter if provided
        if role_path_filter:
            pagination_config['PathPrefix'] = role_path_filter
        
        # Get all roles matching the filter
        total_roles = 0
        aws_managed_skipped = 0
        tag_filtered = 0
        evaluated = 0
        
        for page in roles_paginator.paginate(**pagination_config):
            page_roles = [role['RoleName'] for role in page['Roles']]
            logger.info(f"Processing page with {len(page_roles)} roles: {page_roles}")
            
            for role in page['Roles']:
                total_roles += 1
                role_name = role['RoleName']
                role_arn = role['Arn']
                role_path = role['Path']
                
                logger.info(f"Processing role: {role_name} (path: {role_path})")
                
                # Skip AWS managed roles
                if any(role_path.startswith(aws_path) for aws_path in aws_managed_paths):
                    logger.info(f"SKIPPED - AWS managed role: {role_name}")
                    aws_managed_skipped += 1
                    continue
                
                # Apply tag filter if specified
                if role_tag_filter and not matches_tag_filter(iam_client, role_name, role_tag_filter):
                    logger.info(f"SKIPPED - Tag filter: {role_name}")
                    tag_filtered += 1
                    continue
                
                logger.info(f"EVALUATING: {role_name}")
                evaluation = evaluate_role_by_name(role_name, role_arn, max_wildcard_actions, 
                                                 allowed_wildcard_actions, prohibited_actions, 
                                                 require_resource_restrictions)
                evaluations.append(evaluation)
                evaluated += 1
                logger.info(f"RESULT - {role_name}: {evaluation['ComplianceType']}")
        
        logger.info(f"Summary: {total_roles} total, {aws_managed_skipped} AWS managed skipped, {tag_filtered} tag filtered, {evaluated} evaluated")
    except Exception as e:
        logger.error(f"Error evaluating all roles: {str(e)}")
    
    return evaluations

def matches_tag_filter(iam_client, role_name, tag_filter):
    """Check if role matches the tag filter."""
    try:
        response = iam_client.list_role_tags(RoleName=role_name)
        role_tags = {tag['Key']: tag['Value'] for tag in response['Tags']}
        logger.info(f"Role {role_name} tags: {role_tags}")
        logger.info(f"Tag filter to match: '{tag_filter}'")
        
        # Parse tag filter (format: key=value or key=value1,value2)
        for filter_item in tag_filter.split(';'):
            logger.info(f"Processing filter item: '{filter_item}'")
            if '=' not in filter_item:
                logger.info(f"Skipping filter item (no =): '{filter_item}'")
                continue
            key, values = filter_item.split('=', 1)
            key = key.strip()
            value_list = [v.strip() for v in values.split(',')]
            
            logger.info(f"Checking if role has tag '{key}' with values {value_list}")
            logger.info(f"Role has tag '{key}': {key in role_tags}")
            if key in role_tags:
                logger.info(f"Role tag value: '{role_tags[key]}', Expected values: {value_list}")
                logger.info(f"Value match: {role_tags[key] in value_list}")
            
            if key in role_tags and role_tags[key] in value_list:
                logger.info(f"Role {role_name} MATCHES tag filter: {key}={role_tags[key]}")
                return True
        
        logger.info(f"Role {role_name} does NOT match any tag filter criteria")
        return False
    except Exception as e:
        logger.warning(f"Error checking tags for role {role_name}: {str(e)}")
        return True  # Include role if tag check fails

def evaluate_role(configuration_item, max_wildcard_actions, allowed_wildcard_actions, 
                 prohibited_actions, require_resource_restrictions, role_path_filter=None, role_tag_filter=None):
    """Evaluate a single IAM role from configuration item."""
    role_name = configuration_item.get('resourceName')
    role_arn = configuration_item.get('ARN')
    role_path = configuration_item.get('configuration', {}).get('path', '')
    
    if not role_name:
        return create_evaluation(role_arn or 'unknown', 'AWS::IAM::Role', 'NOT_APPLICABLE', 'Role name not found')
    
    # Skip AWS managed roles
    if role_path.startswith('/aws-service-role/') or role_path.startswith('/service-role/'):
        return create_evaluation(role_arn, 'AWS::IAM::Role', 'NOT_APPLICABLE', 'AWS managed role - excluded from evaluation')
    
    # Check if role matches path filter
    if role_path_filter:
        # Extract role path from ARN or get it from IAM
        actual_role_path = extract_role_path_from_arn(role_arn) or get_role_path(role_name)
        if not actual_role_path or not actual_role_path.startswith(role_path_filter):
            logger.info(f"Role {role_name} with path '{actual_role_path}' does not match path filter '{role_path_filter}' - skipping")
            return create_evaluation(role_arn, 'AWS::IAM::Role', 'NOT_APPLICABLE', f'Role path does not match filter: {role_path_filter}')
    
    # Check if role matches tag filter
    if role_tag_filter:
        if not matches_tag_filter(iam_client, role_name, role_tag_filter):
            logger.info(f"Role {role_name} does not match tag filter '{role_tag_filter}' - skipping")
            return create_evaluation(role_arn, 'AWS::IAM::Role', 'NOT_APPLICABLE', f'Role tags do not match filter: {role_tag_filter}')
    
    return evaluate_role_by_name(role_name, role_arn, max_wildcard_actions, allowed_wildcard_actions, 
                               prohibited_actions, require_resource_restrictions)

def evaluate_role_by_name(role_name, role_arn, max_wildcard_actions, allowed_wildcard_actions, 
                        prohibited_actions, require_resource_restrictions):
    """Evaluate a single IAM role by name."""
    iam_client = boto3.client('iam')
    
    try:
        # Check if role has Bedrock permissions and if they follow least privilege
        has_bedrock_permissions, violations = check_role_bedrock_permissions(
            iam_client, role_name, max_wildcard_actions, allowed_wildcard_actions,
            prohibited_actions, require_resource_restrictions
        )
        
        logger.info(f"Role {role_name}: Bedrock permissions={has_bedrock_permissions}, violations={len(violations)}")
        
        if not has_bedrock_permissions:
            return create_evaluation(role_arn, 'AWS::IAM::Role', 'NOT_APPLICABLE', 'Role has no Bedrock permissions')
        
        if not violations:
            return create_evaluation(role_arn, 'AWS::IAM::Role', 'COMPLIANT', 'Role follows least privilege principles')
        else:
            violation_summary = '; '.join(violations[:3])
            if len(violations) > 3:
                violation_summary += f"; and {len(violations) - 3} more violations"
            return create_evaluation(role_arn, 'AWS::IAM::Role', 'NON_COMPLIANT', violation_summary)
            
    except Exception as e:
        logger.error(f"Error evaluating role {role_name}: {str(e)}")
        return create_evaluation(role_arn, 'AWS::IAM::Role', 'NON_COMPLIANT', f'Error: {str(e)[:200]}')

def check_role_bedrock_permissions(
    iam_client: Any,
    role_name: str,
    max_wildcard_actions: int,
    allowed_wildcard_actions: List[str],
    prohibited_actions: List[str],
    require_resource_restrictions: bool
) -> tuple:
    """
    Check if role has Bedrock permissions and if they follow least privilege principles.
    
    Args:
        iam_client: IAM boto3 client
        role_name: Name of the IAM role
        max_wildcard_actions: Maximum number of wildcard actions allowed
        allowed_wildcard_actions: List of explicitly allowed wildcard actions
        prohibited_actions: List of prohibited Bedrock actions
        require_resource_restrictions: Whether to require resource-level restrictions
        
    Returns:
        Tuple of (has_bedrock_permissions, violations)
    """
    has_bedrock_permissions = False
    all_violations = []
    
    try:
        # Check inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies['PolicyNames']:
            policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            has_bedrock, violations = analyze_policy_document(
                policy_doc['PolicyDocument'],
                f"inline policy {policy_name}",
                max_wildcard_actions,
                allowed_wildcard_actions,
                prohibited_actions,
                require_resource_restrictions
            )
            if has_bedrock:
                has_bedrock_permissions = True
                all_violations.extend(violations)
    except Exception as e:
        logger.warning(f"Cannot access inline policies for role {role_name}: {str(e)}")
    
    try:
        # Get attached managed policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            try:
                policy_arn = policy['PolicyArn']
                # Only check customer-managed policies (not AWS managed policies)
                if not policy_arn.startswith('arn:aws:iam::aws:'):
                    policy_doc = iam_client.get_policy(PolicyArn=policy_arn)
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_doc['Policy']['DefaultVersionId']
                    )
                    has_bedrock, violations = analyze_policy_document(
                        policy_version['PolicyVersion']['Document'],
                        f"managed policy {policy['PolicyName']}",
                        max_wildcard_actions,
                        allowed_wildcard_actions,
                        prohibited_actions,
                        require_resource_restrictions
                    )
                    if has_bedrock:
                        has_bedrock_permissions = True
                        all_violations.extend(violations)
            except Exception as e:
                logger.warning(f"Cannot access policy {policy['PolicyArn']}: {str(e)}")
    except Exception as e:
        logger.warning(f"Cannot list attached policies for role {role_name}: {str(e)}")
    
    return has_bedrock_permissions, all_violations

def analyze_policy_document(
    policy_doc: Dict[str, Any],
    policy_identifier: str,
    max_wildcard_actions: int,
    allowed_wildcard_actions: List[str],
    prohibited_actions: List[str],
    require_resource_restrictions: bool
) -> tuple:
    """
    Analyze a policy document for Bedrock least privilege violations.
    
    Args:
        policy_doc: IAM policy document
        policy_identifier: Identifier for the policy (for logging)
        max_wildcard_actions: Maximum number of wildcard actions allowed
        allowed_wildcard_actions: List of explicitly allowed wildcard actions
        prohibited_actions: List of prohibited Bedrock actions
        require_resource_restrictions: Whether to require resource-level restrictions
        
    Returns:
        Tuple of (has_bedrock_permissions, violations)
    """
    violations = []
    has_bedrock_permissions = False
    
    if 'Statement' not in policy_doc:
        return False, violations
    
    statements = policy_doc['Statement']
    if not isinstance(statements, list):
        statements = [statements]
    
    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue
        
        if 'Action' not in statement:
            continue
        
        actions = statement['Action']
        if not isinstance(actions, list):
            actions = [actions]
        
        # Check for Bedrock-related actions and wildcards
        bedrock_specific_actions = []
        bedrock_wildcards = []
        full_wildcards = []
        
        for action in actions:
            if action == '*':  # Full wildcard (allows everything)
                full_wildcards.append(action)
                has_bedrock_permissions = True
            elif action == 'bedrock:*':  # Bedrock service wildcard
                bedrock_wildcards.append(action)
                has_bedrock_permissions = True
            elif action.startswith('bedrock:'):  # Specific Bedrock action
                bedrock_specific_actions.append(action)
                has_bedrock_permissions = True
        
        # If no Bedrock permissions found, skip this statement
        if not (bedrock_specific_actions or bedrock_wildcards or full_wildcards):
            continue
        
        # Only check wildcards that are relevant to Bedrock
        relevant_wildcards = bedrock_wildcards + full_wildcards
        allowed_wildcards = [action for action in relevant_wildcards if action in allowed_wildcard_actions]
        disallowed_wildcards = [action for action in relevant_wildcards if action not in allowed_wildcard_actions]
        
        if len(disallowed_wildcards) > max_wildcard_actions:
            # Create more specific violation messages
            if '*' in disallowed_wildcards:
                violations.append(
                    f"{policy_identifier} uses full wildcard (*) which grants unrestricted access to all AWS services including Bedrock"
                )
            if 'bedrock:*' in disallowed_wildcards:
                violations.append(
                    f"{policy_identifier} uses Bedrock service wildcard (bedrock:*) which grants unrestricted access to all Bedrock actions"
                )
        
        # Check for prohibited actions
        for prohibited in prohibited_actions:
            if prohibited in bedrock_specific_actions or '*' in actions or 'bedrock:*' in actions:
                violations.append(f"{policy_identifier} allows prohibited action: {prohibited}")
        
        # Check for resource restrictions if required
        if require_resource_restrictions:
            resources = statement.get('Resource', [])
            if not isinstance(resources, list):
                resources = [resources]
            
            if '*' in resources or not resources:
                violations.append(f"{policy_identifier} lacks proper resource restrictions")
    
    return has_bedrock_permissions, violations

def extract_role_path_from_arn(role_arn):
    """Extract role path from ARN if possible."""
    if not role_arn:
        return None
    
    try:
        # ARN format: arn:aws:iam::account:role/path/role-name
        # We need to extract the path part
        parts = role_arn.split(':')
        if len(parts) >= 6 and parts[2] == 'iam' and parts[5].startswith('role/'):
            role_part = parts[5][5:]  # Remove 'role/' prefix
            if '/' in role_part:
                # Has path: extract everything except the last part (role name)
                path_parts = role_part.split('/')
                role_path = '/' + '/'.join(path_parts[:-1]) + '/'
                return role_path
            else:
                # No path, just role name - default path is '/'
                return '/'
    except Exception as e:
        logger.warning(f"Error extracting path from ARN {role_arn}: {str(e)}")
    
    return None

def get_role_path(role_name):
    """Get role path from IAM API."""
    try:
        iam_client = boto3.client('iam')
        response = iam_client.get_role(RoleName=role_name)
        return response['Role'].get('Path', '/')
    except Exception as e:
        logger.warning(f"Error getting path for role {role_name}: {str(e)}")
        return '/'

def create_evaluation(resource_id, resource_type, compliance_type, annotation):
    """Create an evaluation result."""
    return {
        'ComplianceResourceType': resource_type,
        'ComplianceResourceId': resource_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation[:256],  # Truncate to 256 chars
        'OrderingTimestamp': datetime.utcnow()
    }