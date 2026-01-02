import boto3
import json
import logging
import traceback
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)



def handler(event, context):
    """
    AWS Lambda function to remediate non-compliant Bedrock model invocation logging KMS encryption.
    This function configures KMS encryption for model invocation logging.
    """
    logger.info("Starting remediation for Bedrock model invocation logging KMS encryption")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Parse event data
    try:
        # For direct Lambda invocation
        if 'kmsKeyId' in event:
            logger.log(logging.INFO, "Parsing event data for direct Lambda invocation")
            kms_key_id = event['kmsKeyId']
            
        # For AWS Config Remediation
        elif 'invokingEvent' in event:
            logger.log(logging.INFO, "Parsing event data for AWS Config Remediation")
            invoking_event = json.loads(event['invokingEvent'])
            rule_parameters = json.loads(event['ruleParameters']) if 'ruleParameters' in event else {}
            kms_key_id = rule_parameters.get('kmsKeyId')
            
        else:
            # Default values if not provided
            logger.info("No event data provided, using default values")
            kms_key_id = None
    
        logger.info(f"KMS Key ID: {kms_key_id}")
        
        if not kms_key_id:
            logger.error("No KMS Key ID provided")
            return {
                'statusCode': 400,
                'message': "KMS Key ID is required for remediation"
            }
        
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock')
        
        # Get current logging configuration
        logging_config = bedrock_client.get_model_invocation_logging_configuration()
        logger.info(f"Current logging configuration: {logging_config}")
        # Check if logging is enabled
        if 'loggingConfig' not in logging_config:
            logger.info("Model invocation logging is disabled. Skipping remediation as KMS encryption is only applicable when logging is enabled.")
            return {
                'statusCode': 200,
                'message': "Model invocation logging is disabled. Remediation skipped."
            }
        
        # Model invocation logging is enabled, check if KMS is already configured
        current_config = logging_config['loggingConfig']
        kms_already_configured = False
        
        # Check S3 config for KMS
        if 's3Config' in current_config and 'kmsKeyId' in current_config['s3Config']:
            kms_already_configured = True
            logger.info(f"S3 logging already has KMS encryption configured: {current_config['s3Config']['kmsKeyId']}")
        
        # Check CloudWatch config for KMS (check the actual log group)
        if 'cloudWatchConfig' in current_config:
            log_group_name = current_config['cloudWatchConfig'].get('logGroupName')
            logger.info(f"CloudWatch log group name: {log_group_name}")
            if log_group_name:
                logs_client = boto3.client('logs')
                try:
                    log_group_response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                    for log_group in log_group_response.get('logGroups', []):
                        if log_group['logGroupName'] == log_group_name and 'kmsKeyId' in log_group:
                            kms_already_configured = True
                            logger.info(f"CloudWatch log group already has KMS encryption configured: {log_group['kmsKeyId']}")
                            break
                except Exception as e:
                    logger.warning(f"Could not check CloudWatch log group encryption status: {str(e)}")
        
        if kms_already_configured:
            logger.info("Model invocation logging already has KMS encryption configured. No remediation needed.")
            return {
                'statusCode': 200,
                'message': "Model invocation logging already has KMS encryption configured. No remediation needed."
            }
        
        # Model invocation logging is enabled but KMS is not configured - proceed with remediation
        logger.info("Model invocation logging is enabled but KMS encryption is not configured. Proceeding with remediation.")
        
        # Format KMS key ID to ARN if needed for consistent handling
        if not kms_key_id.startswith('arn:aws:kms:') and not kms_key_id.startswith('alias/'):
            # Get region and account ID from context or boto3 session
            if hasattr(context, 'invoked_function_arn') and context.invoked_function_arn:
                region = context.invoked_function_arn.split(':')[3]
                account_id = context.invoked_function_arn.split(':')[4]
            else:
                # Fallback to boto3 session and STS
                region = boto3.Session().region_name
                account_id = boto3.client('sts').get_caller_identity()['Account']
            kms_key_arn = f"arn:aws:kms:{region}:{account_id}:key/{kms_key_id}"
            logger.info(f"Converted KMS Key ID {kms_key_id} to ARN: {kms_key_arn}")
        else:
            kms_key_arn = kms_key_id
            logger.info(f"Using provided KMS Key: {kms_key_arn}")
        
        # Initialize S3 client for bucket encryption configuration
        s3_client = boto3.client('s3')
        
        # Configure S3 bucket encryption if S3 logging is enabled
        if 's3Config' in current_config:
            s3_bucket_name = current_config['s3Config'].get('bucketName')
            if s3_bucket_name:
                logger.info(f"Configuring KMS encryption for S3 bucket: {s3_bucket_name}")
                try:
                    # Apply server-side encryption configuration to the S3 bucket
                    encryption_config = {
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'aws:kms',
                                    'KMSMasterKeyID': kms_key_arn
                                },
                                'BucketKeyEnabled': True
                            }
                        ]
                    }
                    
                    s3_client.put_bucket_encryption(
                        Bucket=s3_bucket_name,
                        ServerSideEncryptionConfiguration=encryption_config
                    )
                    logger.info(f"Successfully configured KMS encryption for S3 bucket {s3_bucket_name} with key: {kms_key_arn}")
                    
                except Exception as e:
                    logger.error(f"Error configuring S3 bucket encryption: {str(e)}")
                    logger.error(f"Bucket: {s3_bucket_name}")
                    logger.error(f"KMS Key: {kms_key_arn}")
                    raise
            else:
                logger.warning("S3 logging is configured but bucket name is not available")
        
        # Configure CloudWatch log group encryption if CloudWatch logging is enabled
        if 'cloudWatchConfig' in current_config:
            log_group_name = current_config['cloudWatchConfig'].get('logGroupName')
            if log_group_name:
                logger.info(f"Configuring KMS encryption for CloudWatch log group: {log_group_name}")
                
                logs_client = boto3.client('logs')
                try:
                    # Check if log group exists first
                    log_groups_response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                    log_group_exists = any(lg['logGroupName'] == log_group_name for lg in log_groups_response.get('logGroups', []))
                    
                    if not log_group_exists:
                        logger.warning(f"Log group {log_group_name} does not exist. It may be created automatically when logging starts.")
                        logger.info("Skipping KMS association for non-existent log group")
                    else:
                        logger.info(f"Log group {log_group_name} exists. Proceeding with KMS key association.")
                        
                        # Validate KMS key exists
                        kms_client = boto3.client('kms')
                        try:
                            key_info = kms_client.describe_key(KeyId=kms_key_arn)
                            logger.info(f"KMS key {kms_key_arn} exists and is in state: {key_info['KeyMetadata']['KeyState']}")
                        except Exception as kms_error:
                            logger.error(f"KMS key validation failed: {str(kms_error)}")
                            raise
                        
                        logs_client.associate_kms_key(
                            logGroupName=log_group_name,
                            kmsKeyId=kms_key_arn
                        )
                        logger.info(f"Successfully configured KMS encryption for CloudWatch log group {log_group_name} with key: {kms_key_arn}")
                        
                except Exception as e:
                    logger.error(f"Error configuring CloudWatch log group encryption: {str(e)}")
                    logger.error(f"Log group: {log_group_name}")
                    logger.error(f"KMS Key: {kms_key_arn}")
                    raise
            else:
                logger.warning("CloudWatch logging is configured but log group name is not available")
        
        logger.info("Successfully configured KMS encryption for Bedrock model invocation logging destinations")
        
        return {
            'statusCode': 200,
            'message': "Bedrock model invocation logging KMS encryption remediation completed successfully"
        }
        
    except Exception as e:
        logger.error(f"Error remediating Bedrock model invocation logging KMS encryption: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'message': f"Error remediating Bedrock model invocation logging KMS encryption: {str(e)}"
        }