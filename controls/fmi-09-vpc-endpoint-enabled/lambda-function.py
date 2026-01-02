import boto3
import json
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = boto3.client('config')

def handler(event, context):
    """Check if VPC endpoints exist for Bedrock connectivity
    Control ID: FMI-09 - bedrock-vpc-endpoint-enabled
    """
    logger.info("Checking Bedrock VPC endpoints")
    
    invoking_event = json.loads(event.get('invokingEvent', '{}'))
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
        
        if available_endpoints:
            compliance_type = 'COMPLIANT'
            annotation = f"Found {len(available_endpoints)} available Bedrock VPC endpoints"
        else:
            compliance_type = 'NON_COMPLIANT'
            annotation = "No available Bedrock VPC endpoints found"
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error checking VPC endpoints: {str(e)}'
    
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