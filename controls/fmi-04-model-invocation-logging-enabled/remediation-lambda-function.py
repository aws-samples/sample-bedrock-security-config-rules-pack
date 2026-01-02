import boto3
import os
import json
import logging
import datetime
import time
import json
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock_client = boto3.client('bedrock')
account_id = boto3.client('sts').get_caller_identity()['Account']
region = boto3.session.Session().region_name
iam_client = boto3.client('iam')
logs_client = boto3.client('logs')
s3_client = boto3.client('s3')
def handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Get parameters from event payload
    logging_destination = event.get('loggingDestination', 'CloudWatch')
    log_group_name = event.get('logGroupName', '/aws/bedrock/modelinvocations')
    s3_bucket_name = event.get('s3BucketName', f"bedrock-model-invocation-logs-{account_id}-{region}")
    logging_role_name = event.get('loggingRoleName')   
    log_retention_days = int(event.get('logRetentionDays', '90'))
              
    
    try:
        # For SSM Automation document invocation
        if 'resourceId' in event:
            resource_id = event['resourceId']
            logger.info(f"Processing resource: {resource_id}")
        
        logger.info("checking current logging configuration")
        response = bedrock_client.get_model_invocation_logging_configuration()
        logger.info(f"Current logging configuration: {response}")
    
        if 'loggingConfig' in response:
            logger.info("Found loggingConfig in response - logging is enabled")
            return {
            'statusCode': 200,
            'message': "Model invocation logging is already configured",
            'configuration': response
        }
        else:
            logger.info("No logging configuration found, setting up now")
            # Set up logging configuration
            role_arn, logging_config = setup_logging_configuration(
                logging_destination, 
                log_group_name, 
                s3_bucket_name,
                log_retention_days, 
                logging_role_name
            )
            # Enable model invocation logging
            bedrock_client.put_model_invocation_logging_configuration(
                loggingConfig=logging_config
            )
            
            logger.info(f"Successfully enabled model invocation logging with destination: {logging_destination}")
            return {
                'statusCode': 200,
                'message': f"Successfully enabled model invocation logging with destination: {logging_destination}"
            }

    except Exception as e:
        logger.error(f"Error in handler: {str(e)}")
        return {
            'statusCode': 500,
            'message': f"Error enabling model invocation logging: {str(e)}"
        }
def setup_logging_configuration(logging_destination, log_group_name, s3_bucket_name, log_retention_days, logging_role_name):
    """Set up logging configuration based on destination"""
    
    role_arn = None
    role_arn = create_or_get_logging_role(logging_role_name, log_group_name,s3_bucket_name )
    
    logger.info(f"Created/retrieved IAM role: {role_arn}")
    # Wait for role to propagate if newly created
    logger.info("Waiting for IAM role to propagate...")
    time.sleep(10)

    # Configure logging based on destination
    logging_config = {}
    
    if logging_destination in ['CloudWatch', 'Both']:
        create_log_group_if_not_exists(log_group_name, log_retention_days)
        logging_config['cloudWatchConfig'] = {
            'logGroupName': log_group_name,
            'roleArn': role_arn
        }
    
    if logging_destination in ['S3', 'Both']:
        region = boto3.session.Session().region_name
        create_s3_bucket_if_not_exists(s3_bucket_name)
        logging_config['s3Config'] = {
            'bucketName': s3_bucket_name,
            'keyPrefix': 'logs/'
            #'roleArn': role_arn
        }
    
    return role_arn, logging_config


def create_or_get_logging_role(logging_role_name, log_group_name, s3_bucket_name):
  """Create or get an IAM role for Bedrock logging"""
        
  try:
      # Check if role already exists
      response = iam_client.get_role(RoleName=logging_role_name)
      logger.info(f"Role {logging_role_name} already exists")
      return response['Role']['Arn']
  except ClientError as e:
      if e.response['Error']['Code'] == 'NoSuchEntity':
          # Create the role
          logger.info(f"Creating new role: {logging_role_name}")
          
          trust_policy = {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "Service": "bedrock.amazonaws.com"
                  },
                  "Action": "sts:AssumeRole",
                  "Condition": {
                    "StringEquals": {
                      "aws:SourceAccount": f"{account_id}" 
                    },
                    "ArnLike": {
                      "aws:SourceArn": f"arn:aws:bedrock:{region}:{account_id}:*"
                    }
                  }
                }
              ]
            }
          
          role = iam_client.create_role(
              RoleName=logging_role_name,
              AssumeRolePolicyDocument=json.dumps(trust_policy),
              Description="Role for Bedrock model invocation logging",
              Tags=[
                  {
                      'Key': 'Purpose',
                      'Value': 'BedrockModelInvocationLogging'
                  }
              ]
          )
          
          # Attach policies for CloudWatch Logs and S3
          policy_document = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AmazonBedrockModelInvocationCWDeliveryRole",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
                           "Resource": [
                                f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*",
                                f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"
                            ]


                        },
                        {
                            "Sid": "AmazonBedrockModelInvocationS3Role",
                            "Effect": "Allow",
                            "Action": [
                                
                                "s3:PutObject",
                                
                            ],
                            "Resource": [
                            #bucket arn from bucketName
                            f"arn:aws:s3:::{s3_bucket_name}",
                            f"arn:aws:s3:::{s3_bucket_name}/*"
                            
                            ]
                        }
                    ]
                }
          
          iam_client.put_role_policy(
              RoleName=logging_role_name,
              PolicyName="BedrockModelInvocationLogsPolicy",
              PolicyDocument=json.dumps(policy_document)
          )
          
          return role['Role']['Arn']
      else:
          raise
def create_log_group_if_not_exists(log_group_name, retention_days):
  """Create CloudWatch Logs log group if it doesn't exist"""
  try:
      # Check if log group exists
      response = logs_client.describe_log_groups(
          logGroupNamePrefix=log_group_name,
          limit=1
      )
      
      if not response.get('logGroups') or response['logGroups'][0]['logGroupName'] != log_group_name:
          # Create log group
          logs_client.create_log_group(
              logGroupName=log_group_name,
              tags={
                  'Purpose': 'BedrockModelInvocationLogging'
              }
          )
          logger.info(f"Created log group: {log_group_name}")
          
          # Set retention policy
          logs_client.put_retention_policy(
              logGroupName=log_group_name,
              retentionInDays=retention_days
          )
          logger.info(f"Set log retention to {retention_days} days")
      else:
          logger.info(f"Log group {log_group_name} already exists")
          
          # Update retention policy
          logs_client.put_retention_policy(
              logGroupName=log_group_name,
              retentionInDays=retention_days
          )
          logger.info(f"Updated log retention to {retention_days} days")
          
  except ClientError as e:
      logger.error(f"Error creating/checking log group: {str(e)}")
      raise

def create_s3_bucket_if_not_exists(bucket_name):
    """Create S3 bucket if it doesn't exist"""
    try:
        # Check if bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        logger.info(f"S3 bucket {bucket_name} already exists")
    except ClientError as e:
        error_code = int(e.response['Error']['Code']) if e.response['Error']['Code'].isdigit() else e.response['Error']['Code']
        if error_code == 404 or error_code == '404':
            # Create bucket
            region = boto3.session.Session().region_name
            try:
                if region == 'us-east-1':
                    s3_client.create_bucket(
                        Bucket=bucket_name
                    )
                else:
                    s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={
                            'LocationConstraint': region
                        }
                    )
                
                logger.info(f"Created S3 bucket: {bucket_name}")
                
                # Enable versioning
                s3_client.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={
                        'Status': 'Enabled'
                    }
                )
                
                # Enable encryption
                s3_client.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                },
                                'BucketKeyEnabled': True
                            }
                        ]
                    }
                )
                # add bucket policy to allow bedrock to write to bucket
                s3_client.put_bucket_policy(
                    Bucket=bucket_name,
                    Policy=json.dumps({
                        'Version': '2012-10-17',
                        'Statement': [
                            {
                                'Sid': 'AllowBedrockToWriteToBucketBEDSCR',
                                'Effect': 'Allow',
                                'Principal': {
                                    'Service': 'bedrock.amazonaws.com'
                                },
                                'Action': 's3:PutObject',
                                'Resource': f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/BedrockModelInvocationLogs/*",
                                'Condition': {
                                    "StringEquals": {
                                        "aws:SourceAccount": f"{account_id}"
                                    },
                                    "ArnLike": {
                                        "aws:SourceArn": f"arn:aws:bedrock:{region}:{account_id}:*"
                                    }
                                }
                            }
                        ]
                    })
                )

                logger.info(f"Updated bucket policy for model invocation logging : {bucket_name}")


                # Block public access
                s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                
                # Add tags
                s3_client.put_bucket_tagging(
                    Bucket=bucket_name,
                    Tagging={
                        'TagSet': [
                            {
                                'Key': 'Purpose',
                                'Value': 'BedrockModelInvocationLogging'
                            }
                        ]
                    }
                )
            except ClientError as bucket_error:
                logger.error(f"Error creating S3 bucket: {str(bucket_error)}")
                raise
        else:
            logger.error(f"Error checking S3 bucket: {str(e)}")
            raise
