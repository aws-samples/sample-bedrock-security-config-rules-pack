import boto3
import json
import logging
import traceback
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS Config client
config = boto3.client('config')

def handler(event, context):
    """
    AWS Config rule to check if KMS encryption is enabled for Bedrock model invocation logging.
    Control ID: FMI-06 - bedrock-model-logs-kms-check
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        logger.error(traceback.format_exc())
        invoking_event = {}
        rule_parameters = {}

    # Get account ID
    account_id = event.get('accountId')
    if not account_id:
        account_id = context.invoked_function_arn.split(':')[4]
    logger.info(f"Account ID: {account_id}")

    # Get result token
    result_token = event.get('resultToken')
    logger.info(f"Result token available: {bool(result_token)}")

    # Get required parameters
    required_kms_key_ids_param = rule_parameters.get('requiredKmsKeyIds', '')
    if required_kms_key_ids_param and required_kms_key_ids_param.lower() != 'null':
        required_kms_key_ids = [key_id.strip() for key_id in required_kms_key_ids_param.split(',') if key_id.strip()]
    else:
        required_kms_key_ids = []
    
    logger.info(f"Required KMS Key IDs: {required_kms_key_ids}")
    
    try:
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock')
        
        # Check for KMS encryption in model invocation logging
        logger.info("Checking model invocation logging configuration for KMS encryption")
        try:
            logging_config = bedrock_client.get_model_invocation_logging_configuration()
            logger.info(f"Model invocation logging configuration: {logging_config}")
            
            # Check if logging is enabled
            if 'loggingConfig' not in logging_config:
                logger.info("Model invocation logging is not enabled")
                compliance_type = 'NON_COMPLIANT'
                annotation = "Model invocation logging is not enabled, cannot verify KMS encryption"
                return put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event)
            
            # Check S3 logging configuration for KMS encryption
            s3_encryption_compliant = False
            if 's3Config' in logging_config['loggingConfig']:
                logger.info("S3 logging is enabled")
                #get s3 bucket name
                bucket_name = logging_config['loggingConfig']['s3Config']['bucketName']
                #initialize s3 client and get bucket encryption
                s3_client = boto3.client('s3')
                bucket_encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                logger.info(f"Bucket encryption: {bucket_encryption}")
                #check if bucket encryption is enabled
                if 'ServerSideEncryptionConfiguration' in bucket_encryption:
                    rules = bucket_encryption['ServerSideEncryptionConfiguration']['Rules']
                    for rule in rules:
                        if 'ApplyServerSideEncryptionByDefault' in rule:
                            #SSEAlgorithm should be kms
                            if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != 'aws:kms':
                                logger.info("S3 logging does not use KMS encryption")
                                continue
                            else:
                                logger.info("S3 logging uses KMS encryption")
                                if required_kms_key_ids:
                                    if rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID'] in required_kms_key_ids:
                                        s3_encryption_compliant = True
                                        logger.info(f"S3 logging uses compliant KMS key: {rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']}")
                                    else:
                                        logger.info(f"S3 logging uses non-compliant KMS key: {rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']}")
                                else:
                                    s3_encryption_compliant = True
                                    logger.info("S3 logging uses KMS encryption, but no specific KMS key ID is required")   
                                continue
                            
                        else:
                            logger.info("S3 logging does not use KMS encryption")
                else:
                    logger.info("S3 logging does not use KMS encryption")
            
            # Check CloudWatch logging configuration for KMS encryption
            cloudwatch_encryption_compliant = False
            if 'cloudWatchConfig' in logging_config['loggingConfig']:
                cloudwatch_config = logging_config['loggingConfig']['cloudWatchConfig']
                # CloudWatch Logs encryption is managed at the log group level
                # We need to check if the log group is encrypted with KMS
                log_group_name = cloudwatch_config.get('logGroupName')
                if log_group_name:
                    logs_client = boto3.client('logs')
                    try:
                        log_group = logs_client.describe_log_groups(
                            logGroupNamePrefix=log_group_name,
                            limit=1
                        )
                        if log_group['logGroups'] and 'kmsKeyId' in log_group['logGroups'][0]:
                            kms_key_id = log_group['logGroups'][0]['kmsKeyId']
                            if not required_kms_key_ids or kms_key_id in required_kms_key_ids:
                                cloudwatch_encryption_compliant = True
                                logger.info(f"CloudWatch logging uses compliant KMS key: {kms_key_id}")
                            else:
                                logger.info(f"CloudWatch logging uses non-compliant KMS key: {kms_key_id}")
                        else:
                            logger.info("CloudWatch logging does not use KMS encryption")
                    except Exception as e:
                        logger.error(f"Error checking CloudWatch log group encryption: {str(e)}")
            
            # Determine compliance
            if s3_encryption_compliant or cloudwatch_encryption_compliant:
                compliance_type = 'COMPLIANT'
                annotation = "Model invocation logging uses KMS encryption with approved keys"
            else:
                compliance_type = 'NON_COMPLIANT'
                annotation = "Model invocation logging does not use KMS encryption with approved keys"
            
        except Exception as e:
            logger.error(f"Error checking model invocation logging: {str(e)}")
            logger.error(traceback.format_exc())
            compliance_type = 'NON_COMPLIANT'
            annotation = f"Error checking model invocation logging KMS encryption: {str(e)}"
            
    except Exception as e:
        logger.error(f"Error evaluating Bedrock model logs KMS encryption: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock model logs KMS encryption: {str(e)}'
    
    return put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event)

def put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event):
    """
    Put evaluation results to AWS Config and return the result.
    """
    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.utcnow().isoformat()
    
    # Put evaluation
    evaluation = {
        'ComplianceResourceType': 'AWS::::Account',
        'ComplianceResourceId': account_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': ordering_timestamp
    }
    
    if result_token:
        config.put_evaluations(
            Evaluations=[evaluation],
            ResultToken=result_token
        )
    
    logger.info(f"Evaluation result: {compliance_type} - {annotation}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'complianceType': compliance_type,
            'annotation': annotation
        })
    }