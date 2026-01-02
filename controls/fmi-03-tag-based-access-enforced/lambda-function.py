import boto3
import json
import logging
import traceback
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
config = boto3.client('config')
iam = boto3.client('iam')

def handler(event, context):
    """
    AWS Config rule to check if IAM roles granting Bedrock permissions
    include proper tag-based access control conditions.
    Control ID: FMI-03 - bedrock-tag-based-access-enforced
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        configuration_item = invoking_event.get('configurationItem', {})
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        logger.error(traceback.format_exc())
        invoking_event = {}
        rule_parameters = {}
        configuration_item = {}

    # Get result token
    result_token = event.get('resultToken')
    logger.info(f"Result token available: {bool(result_token)}")

    # Get required parameters
    required_tag_keys = rule_parameters.get('requiredTagKeys', '').split(',')
    required_tag_keys = [tag_key.strip() for tag_key in required_tag_keys if tag_key.strip()]
    #if there are no tags, send error
    if not required_tag_keys:
        logger.error("No required tag keys specified")
        if result_token:
            config.put_evaluations(
                Evaluations=[
                    {
                        'ComplianceResourceType': 'AWS::IAM::Role',
                        'ComplianceResourceId': 'N/A',
                        'ComplianceType': 'NON_COMPLIANT',
                        'OrderingTimestamp': datetime.now().isoformat(),
                        'Annotation': 'No required tag keys specified'
                    }
                ],
                ResultToken=result_token
            )

        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'No required tag keys specified'
            })
        }
    
    # Minimum number of tag conditions required
    min_tag_conditions = int(rule_parameters.get('minTagConditions'))
    
    # Optional filters
    role_path_filter = rule_parameters.get('rolePathFilter', '').strip() or None
    role_tag_filter = rule_parameters.get('roleTagFilter', '').strip() or None
    
    logger.info(f"Required tag keys: {required_tag_keys}")
    logger.info(f"Minimum tag conditions required: {min_tag_conditions}")
    logger.info(f"Role path filter: {role_path_filter}")
    logger.info(f"Role tag filter: {role_tag_filter}")
    
    # Handle different invocation types
    if configuration_item:
        # Configuration change triggered - check if role matches filters
        logger.info("Resource-based evaluation triggered")
        evaluations = [evaluate_role(configuration_item, required_tag_keys, min_tag_conditions, role_path_filter, role_tag_filter)]
    else:
        # Periodic evaluation - check all roles
        logger.info("Periodic evaluation triggered")
        evaluations = evaluate_all_roles(required_tag_keys, min_tag_conditions, role_path_filter, role_tag_filter)
       
    logger.info(f"Evaluations: {json.dumps(evaluations, default=str)}")
    # Submit evaluations
    if result_token and evaluations:
        config.put_evaluations(
            Evaluations=evaluations,
            ResultToken=result_token
        )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'evaluationsCount': len(evaluations)
        })
    }

def evaluate_all_roles(required_tag_keys, min_tag_conditions, role_path_filter=None, role_tag_filter=None):
    """Evaluate all IAM roles for compliance."""
    evaluations = []
    
    try:
        # Get roles with optional path filter
        if role_path_filter:
            roles_paginator = iam.get_paginator('list_roles')
            pages = roles_paginator.paginate(PathPrefix=role_path_filter)
        else:
            roles_paginator = iam.get_paginator('list_roles')
            pages = roles_paginator.paginate()
            
        for page in pages:
            for role in page['Roles']:
                # Apply tag filter if specified
                if role_tag_filter and not matches_tag_filter(iam, role['RoleName'], role_tag_filter):
                    continue
                    
                evaluation = evaluate_role_by_name(role['RoleName'], required_tag_keys, min_tag_conditions)
                evaluations.append(evaluation)
    except Exception as e:
        logger.error(f"Error evaluating all roles: {str(e)}")
        logger.error(traceback.format_exc())
    
    return evaluations

def matches_tag_filter(iam_client, role_name, tag_filter):
    """Check if role matches the tag filter."""
    try:
        response = iam_client.list_role_tags(RoleName=role_name)
        role_tags = {tag['Key']: tag['Value'] for tag in response['Tags']}
        
        # Parse tag filter (format: key=value or key=value1,value2)
        for filter_item in tag_filter.split(';'):
            if '=' not in filter_item:
                continue
            key, values = filter_item.split('=', 1)
            key = key.strip()
            value_list = [v.strip() for v in values.split(',')]
            
            if key in role_tags and role_tags[key] in value_list:
                return True
        return False
    except Exception as e:
        logger.warning(f"Error checking tags for role {role_name}: {str(e)}")
        return True  # Include role if tag check fails

def evaluate_role(configuration_item, required_tag_keys, min_tag_conditions, role_path_filter=None, role_tag_filter=None):
    """Evaluate a single IAM role from configuration item."""
    role_name = configuration_item.get('resourceName')
    role_arn = configuration_item.get('ARN')
    
    if not role_name:
        return create_evaluation(role_arn or 'unknown', 'AWS::IAM::Role', 'NOT_APPLICABLE', 'Role name not found')
    
    # Check if role matches path filter
    if role_path_filter:
        # Extract role path from ARN or get it from IAM
        role_path = extract_role_path_from_arn(role_arn) or get_role_path(role_name)
        if not role_path or not role_path.startswith(role_path_filter):
            logger.info(f"Role {role_name} with path '{role_path}' does not match path filter '{role_path_filter}' - skipping")
            return create_evaluation(role_name, 'AWS::IAM::Role', 'NOT_APPLICABLE', f'Role path does not match filter: {role_path_filter}')
    
    # Check if role matches tag filter
    if role_tag_filter:
        if not matches_tag_filter(iam, role_name, role_tag_filter):
            logger.info(f"Role {role_name} does not match tag filter '{role_tag_filter}' - skipping")
            return create_evaluation(role_name, 'AWS::IAM::Role', 'NOT_APPLICABLE', f'Role tags do not match filter: {role_tag_filter}')
    
    return evaluate_role_by_name(role_name, required_tag_keys, min_tag_conditions)

def evaluate_role_by_name(role_name, required_tag_keys, min_tag_conditions):
    """Evaluate a single IAM role by name."""
    try:
        # Get the actual role to ensure we have the correct ARN and path
        role_response = iam.get_role(RoleName=role_name)
        role_arn = role_response['Role']['Arn']
        
        # Check if role has Bedrock permissions
        has_bedrock_permissions, has_proper_tag_conditions = check_role_bedrock_permissions(
            iam, role_name, required_tag_keys, min_tag_conditions
        )
        
        if not has_bedrock_permissions:
            return create_evaluation(role_name, 'AWS::IAM::Role', 'NOT_APPLICABLE', 'Role has no Bedrock permissions')
        
        if has_proper_tag_conditions:
            return create_evaluation(role_name, 'AWS::IAM::Role', 'COMPLIANT', 'Role has proper tag-based access control')
        else:
            return create_evaluation(role_name, 'AWS::IAM::Role', 'NON_COMPLIANT', 'Role lacks proper tag-based access control')
            
    except Exception as e:
        logger.error(f"Error evaluating role {role_name}: {str(e)}")
        # Use role name as resource ID for proper Config console linking
        return create_evaluation(role_name, 'AWS::IAM::Role', 'NON_COMPLIANT', f'Error: {str(e)[:200]}')

def check_role_bedrock_permissions(iam_client, role_name, required_tag_keys, min_tag_conditions):
    """Check if role has Bedrock permissions and proper tag conditions."""
    has_bedrock_permissions = False
    bedrock_policies_with_tags = 0
    bedrock_policies_total = 0
    
    try:
        # Get inline policies
        inline_policies = iam.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies['PolicyNames']:
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            bedrock_perms, tag_conditions = check_policy_for_bedrock_and_tags(
                policy_doc['PolicyDocument'], required_tag_keys, min_tag_conditions
            )
            if bedrock_perms:
                has_bedrock_permissions = True
                bedrock_policies_total += 1
                if tag_conditions:
                    bedrock_policies_with_tags += 1
                logger.info(f"Inline policy '{policy_name}': Bedrock permissions={bedrock_perms}, Tag conditions={tag_conditions}")
    except Exception as e:
        logger.warning(f"Cannot access inline policies for role {role_name}: {str(e)}")
    
    try:
        # Get attached managed policies
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            try:
                policy_doc = iam.get_policy(PolicyArn=policy['PolicyArn'])
                policy_version = iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=policy_doc['Policy']['DefaultVersionId']
                )
                bedrock_perms, tag_conditions = check_policy_for_bedrock_and_tags(
                    policy_version['PolicyVersion']['Document'], required_tag_keys, min_tag_conditions
                )
                if bedrock_perms:
                    has_bedrock_permissions = True
                    bedrock_policies_total += 1
                    if tag_conditions:
                        bedrock_policies_with_tags += 1
                    logger.info(f"Managed policy '{policy['PolicyName']}': Bedrock permissions={bedrock_perms}, Tag conditions={tag_conditions}")
            except Exception as e:
                logger.warning(f"Cannot access policy {policy['PolicyArn']}: {str(e)}")
    except Exception as e:
        logger.warning(f"Cannot list attached policies for role {role_name}: {str(e)}")
    
    # ALL policies with Bedrock permissions must have proper tag conditions
    has_proper_tag_conditions = (bedrock_policies_total > 0 and bedrock_policies_with_tags == bedrock_policies_total)
    
    logger.info(f"Role {role_name}: {bedrock_policies_total} policies with Bedrock permissions, {bedrock_policies_with_tags} with proper tag conditions")
    
    return has_bedrock_permissions, has_proper_tag_conditions

def check_policy_for_bedrock_and_tags(policy_doc, required_tag_keys, min_tag_conditions):
    """Check if policy grants Bedrock permissions and has proper tag conditions."""
    has_bedrock_permissions = False
    has_proper_tag_conditions = False
    
    if 'Statement' not in policy_doc:
        return False, False
    
    for statement in policy_doc['Statement']:
        if statement.get('Effect') != 'Allow' or 'Action' not in statement:
            continue
            
        actions = statement['Action']
        if isinstance(actions, str):
            actions = [actions]
        
        # Check for Bedrock actions (specific, service wildcard, or full wildcard)
        bedrock_actions = [action for action in actions 
                         if action.startswith('bedrock:') or action == '*' or action == 'bedrock:*']
        
        if bedrock_actions:
            has_bedrock_permissions = True
            
            # Check for tag-based conditions
            if 'Condition' in statement:
                conditions = statement['Condition']
                tag_conditions_found = 0
                
                for condition_type, condition_values in conditions.items():
                    if isinstance(condition_values, dict):
                        for key in condition_values.keys():
                            # Check for aws:ResourceTag conditions
                            if key.startswith('aws:ResourceTag/'):
                                tag_key = key.replace('aws:ResourceTag/', '')
                                if tag_key in required_tag_keys:
                                    tag_conditions_found += 1
                            # Check for direct tag key conditions
                            elif key in required_tag_keys:
                                tag_conditions_found += 1
                
                if tag_conditions_found >= min_tag_conditions:
                    has_proper_tag_conditions = True
    
    return has_bedrock_permissions, has_proper_tag_conditions

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
        response = iam.get_role(RoleName=role_name)
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