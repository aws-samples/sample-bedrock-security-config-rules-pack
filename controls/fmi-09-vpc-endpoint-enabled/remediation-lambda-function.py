import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """Create VPC endpoints for Bedrock services"""
    logger.info("Creating Bedrock VPC endpoints")
    
    try:
        # Parse parameters
        vpc_id = event.get('vpcId')
        subnet_ids = event.get('subnetIds', '').split(',') if event.get('subnetIds') else []
        security_group_ids = event.get('securityGroupIds', '').split(',') if event.get('securityGroupIds') else []
        
        if not vpc_id:
            return {'statusCode': 400, 'message': 'VPC ID is required'}
        
        ec2 = boto3.client('ec2')
        region = boto3.Session().region_name
        created_endpoints = []
        
        # Bedrock services that need VPC endpoints
        services = [
            f'com.amazonaws.{region}.bedrock',
            f'com.amazonaws.{region}.bedrock-runtime'
        ]
        
        for service in services:
            # Check if endpoint already exists
            existing = ec2.describe_vpc_endpoints(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'service-name', 'Values': [service]}
                ]
            )
            
            if existing['VpcEndpoints']:
                logger.info(f"VPC endpoint for {service} already exists")
                continue
            
            # Create VPC endpoint
            endpoint_config = {
                'VpcId': vpc_id,
                'ServiceName': service,
                'VpcEndpointType': 'Interface'
            }
            
            if subnet_ids:
                endpoint_config['SubnetIds'] = [s.strip() for s in subnet_ids if s.strip()]
            if security_group_ids:
                endpoint_config['SecurityGroupIds'] = [s.strip() for s in security_group_ids if s.strip()]
            
            response = ec2.create_vpc_endpoint(**endpoint_config)
            created_endpoints.append(response['VpcEndpoint']['VpcEndpointId'])
            logger.info(f"Created VPC endpoint {response['VpcEndpoint']['VpcEndpointId']} for {service}")
        
        return {
            'statusCode': 200,
            'message': f"Successfully created {len(created_endpoints)} VPC endpoints",
            'endpointIds': created_endpoints
        }
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return {'statusCode': 500, 'message': f'Error creating VPC endpoints: {str(e)}'}