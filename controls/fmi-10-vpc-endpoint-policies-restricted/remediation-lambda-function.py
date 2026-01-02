import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """Remediate overly permissive VPC endpoint policies for Bedrock
    Control ID: FMI-10 - bedrock-vpc-endpoint-policy-restricted
    """
    logger.info("Remediating Bedrock VPC endpoint policy restrictions")
    
    try:
        # Parse event data
        if 'invokingEvent' in event:
            rule_parameters = json.loads(event.get('ruleParameters', '{}'))
        else:
            rule_parameters = event
            
        if not rule_parameters.get('PolicyConditionKey'):
            raise ValueError('PolicyConditionKey parameter is required')
        if not rule_parameters.get('PolicyConditionValues'):
            raise ValueError('PolicyConditionValues parameter is required')
            
        condition_key = rule_parameters['PolicyConditionKey']
        condition_values = rule_parameters['PolicyConditionValues'].split(',')
        
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
        
        remediated_endpoints = []
        
        for endpoint in available_endpoints:
            endpoint_id = endpoint['VpcEndpointId']
            policy_document = endpoint.get('PolicyDocument')
            
            needs_remediation = False
            
            if not policy_document:
                needs_remediation = True
            else:
                try:
                    policy = json.loads(policy_document)
                    if is_policy_overly_permissive(policy, condition_key, condition_values):
                        needs_remediation = True
                except json.JSONDecodeError:
                    needs_remediation = True
            
            if needs_remediation:
                # Apply a restrictive policy
                restrictive_policy = create_restrictive_policy(condition_key, condition_values)
                
                ec2.modify_vpc_endpoint(
                    VpcEndpointId=endpoint_id,
                    PolicyDocument=json.dumps(restrictive_policy)
                )
                
                remediated_endpoints.append(endpoint_id)
                logger.info(f"Applied restrictive policy to VPC endpoint: {endpoint_id}")
        
        if remediated_endpoints:
            message = f"Successfully applied restrictive policies to {len(remediated_endpoints)} VPC endpoints"
        else:
            message = "No VPC endpoints required policy remediation"
            
        return {
            'statusCode': 200,
            'message': message,
            'remediatedEndpoints': remediated_endpoints
        }
        
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        return {
            'statusCode': 400,
            'message': f'Configuration error: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'message': f'Remediation failed: {str(e)}'
        }

def is_policy_overly_permissive(policy, condition_key, condition_values):
    """Check if VPC endpoint policy is overly permissive"""
    statements = policy.get('Statement', [])
    
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
            if condition_key not in string_equals:
                return True
                
            actual_values = string_equals[condition_key]
            if isinstance(actual_values, str):
                actual_values = [actual_values]
            if not all(val in condition_values for val in actual_values):
                return True
    
    return False

def create_restrictive_policy(condition_key, condition_values):
    """Create a restrictive VPC endpoint policy for Bedrock"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:root"
                },
                "Action": [
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        condition_key: condition_values
                    }
                }
            }
        ]
    }