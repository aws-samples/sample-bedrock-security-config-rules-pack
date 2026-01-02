import boto3
import json
import logging
import os
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = boto3.client('config')

def handler(event, context):
    """Check if VPC endpoint policies are properly restricted for Bedrock
    Control ID: FMI-10 - bedrock-vpc-endpoint-policy-restricted
    """
    logger.info("Checking Bedrock VPC endpoint policy restrictions")
    
    invoking_event = json.loads(event.get('invokingEvent', '{}'))
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    account_id = event.get('accountId') or context.invoked_function_arn.split(':')[4]
    result_token = event.get('resultToken')
    
    try:
        ec2 = boto3.client('ec2')
        
        # Get all VPC endpoints for Bedrock services
        response = ec2.describe_vpc_endpoints(
            Filters=[
                {'Name': 'service-name', 'Values': [
                    f'com.amazonaws.{boto3.Session().region_name}.bedrock',
                    f'com.amazonaws.{boto3.Session().region_name}.bedrock-runtime'
                ]}
            ]
        )
        
        endpoints = response['VpcEndpoints']
        available_endpoints = [ep for ep in endpoints if ep['State'] == 'available']
        
        if not available_endpoints:
            compliance_type = 'NOT_APPLICABLE'
            annotation = "No Bedrock VPC endpoints found"
        else:
            non_compliant_endpoints = []
            
            for endpoint in available_endpoints:
                policy_document = endpoint.get('PolicyDocument')
                
                if not policy_document:
                    # No policy means full access - non-compliant
                    non_compliant_endpoints.append(endpoint['VpcEndpointId'])
                else:
                    # Parse policy and check for overly permissive statements
                    try:
                        policy = json.loads(policy_document)
                        if is_policy_overly_permissive(policy, rule_parameters):
                            non_compliant_endpoints.append(endpoint['VpcEndpointId'])
                    except (json.JSONDecodeError, ValueError) as e:
                        non_compliant_endpoints.append(endpoint['VpcEndpointId'])
                        logger.error(f"Policy validation error for {endpoint['VpcEndpointId']}: {str(e)}")
            
            if non_compliant_endpoints:
                compliance_type = 'NON_COMPLIANT'
                annotation = f"VPC endpoints with overly permissive policies: {', '.join(non_compliant_endpoints)}"
            else:
                compliance_type = 'COMPLIANT'
                annotation = f"All {len(available_endpoints)} Bedrock VPC endpoints have restricted policies"
                
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Rule configuration error: {str(e)}'
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error checking VPC endpoint policies: {str(e)}'
    
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': account_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': datetime.utcnow().isoformat()
    }
    
    if result_token:
        config.put_evaluations(Evaluations=[evaluation], ResultToken=result_token)
    
    return {'statusCode': 200, 'body': json.dumps({'complianceType': compliance_type, 'annotation': annotation})}

def is_policy_overly_permissive(policy, rule_parameters):
    """Check if VPC endpoint policy is overly permissive"""
    statements = policy.get('Statement', [])
    
    if not rule_parameters.get('PolicyConditionKey'):
        raise ValueError('PolicyConditionKey parameter is required')
    if not rule_parameters.get('PolicyConditionValues'):
        raise ValueError('PolicyConditionValues parameter is required')
        
    expected_condition_key = rule_parameters['PolicyConditionKey']
    expected_condition_values = rule_parameters['PolicyConditionValues'].split(',')
    
    for statement in statements:
        if statement.get('Effect') == 'Allow':
            # Check for wildcard principals
            principal = statement.get('Principal', {})
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                return True
            
            # Check for wildcard actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            if '*' in actions or 'bedrock:*' in actions:
                return True
                
            # Check if proper conditions are present
            conditions = statement.get('Condition', {})
            if not conditions:
                return True
                
            string_equals = conditions.get('StringEquals', {})
            if expected_condition_key not in string_equals:
                return True
                
            actual_values = string_equals[expected_condition_key]
            if isinstance(actual_values, str):
                actual_values = [actual_values]
            if not all(val in expected_condition_values for val in actual_values):
                return True
    
    return False