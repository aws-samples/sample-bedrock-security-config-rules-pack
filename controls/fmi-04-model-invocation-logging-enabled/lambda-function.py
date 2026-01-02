import boto3
import json
import datetime
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Initialize AWS Config client
logger.info("Initializing AWS Config client")
config = boto3.client('config')

# Initialize Bedrock client
logger.info("Initializing AWS Bedrock client")
bedrock = boto3.client('bedrock')

def handler(event, context):
    """
    AWS Config rule to check if model invocation logs are enabled for Amazon Bedrock.
    Control ID: FMI-04 - bedrock-model-invocation-logging-enabled
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        logger.info("Parsing invokingEvent")
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        logger.info(f"Invoking event parsed: {json.dumps(invoking_event, default=str)}")
    except Exception as e:
        logger.error(f"Error parsing invokingEvent: {str(e)}")
        logger.error(traceback.format_exc())
        invoking_event = {}

    # Get account ID
    account_id = event.get('accountId')
    if not account_id:
        logger.info("Account ID not found in event, extracting from Lambda context")
        account_id = context.invoked_function_arn.split(':')[4]
    logger.info(f"Account ID: {account_id}")

    # Get result token
    result_token = event.get('resultToken')
    logger.info(f"Result token available: {bool(result_token)}")



    try:
        # Get the model invocation logging configuration
        logger.info("Calling Bedrock get_model_invocation_logging_configuration API")
        response = bedrock.get_model_invocation_logging_configuration()
        logger.info(f"Bedrock API response: {json.dumps(response, default=str)}")

        # Check if logging is enabled by looking for loggingConfig
        if 'loggingConfig' in response:
            logger.info("Found loggingConfig in response - logging is enabled")

            # Extract configuration details
            logging_config = response.get('loggingConfig', {})

            # Get CloudWatch configuration if available
            cloudwatch_config = logging_config.get('cloudWatchConfig', {})
            cloudwatch_log_group = cloudwatch_config.get('logGroupName', 'Not configured')
            cloudwatch_role_arn = cloudwatch_config.get('roleArn', 'Not configured')

            # Get CloudWatch large data delivery S3 config if available
            large_data_s3_config = cloudwatch_config.get('largeDataDeliveryS3Config', {})
            large_data_bucket = large_data_s3_config.get('bucketName', 'Not configured')
            large_data_prefix = large_data_s3_config.get('keyPrefix', '')

            # Get S3 configuration if available
            s3_config = logging_config.get('s3Config', {})
            s3_bucket = s3_config.get('bucketName', 'Not configured')
            s3_prefix = s3_config.get('keyPrefix', '')

            # Get data delivery settings
            text_enabled = logging_config.get('textDataDeliveryEnabled', False)
            image_enabled = logging_config.get('imageDataDeliveryEnabled', False)
            embedding_enabled = logging_config.get('embeddingDataDeliveryEnabled', False)
            video_enabled = logging_config.get('videoDataDeliveryEnabled', False)

            # Build list of enabled data types
            enabled_types = []
            if text_enabled:
                enabled_types.append("text")
            if image_enabled:
                enabled_types.append("image")
            if embedding_enabled:
                enabled_types.append("embedding")
            if video_enabled:
                enabled_types.append("video")

            # Determine if any destination is configured
            has_cloudwatch = cloudwatch_log_group != 'Not configured'
            has_s3 = s3_bucket != 'Not configured'

            if has_cloudwatch or has_s3:
                # Build detailed annotation
                details = []
                if has_cloudwatch:
                    details.append(f"CloudWatch log group: {cloudwatch_log_group}")
                if has_s3:
                    details.append(f"S3 bucket: {s3_bucket}")
                if enabled_types:
                    details.append(f"Data types: {', '.join(enabled_types)}")

                compliance_type = 'COMPLIANT'
                annotation = f"Model invocation logging is enabled for Amazon Bedrock. {'; '.join(details)}"
            else:
                compliance_type = 'NON_COMPLIANT'
                annotation = 'Model invocation logging is configured but no destination (CloudWatch or S3) is specified.'
        else:
            logger.info("No logging configuration found")
            compliance_type = 'NON_COMPLIANT'
            annotation = 'Model invocation logging is not enabled for Amazon Bedrock.'

    except Exception as e:
        logger.error(f"Error checking model invocation logging configuration: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error checking model invocation logging configuration: {str(e)}'

    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        logger.info("notificationCreationTime not found, using current UTC time")
        ordering_timestamp = datetime.datetime.utcnow().isoformat()
    logger.info(f"Ordering timestamp: {ordering_timestamp}")

    # Put evaluation results
    if result_token:
        logger.info("Putting evaluation results to AWS Config")
        try:
            evaluation_result = config.put_evaluations(
                Evaluations=[
                    {
                        'ComplianceResourceType': 'AWS::::Account',
                        'ComplianceResourceId': account_id,
                        'ComplianceType': compliance_type,
                        'Annotation': annotation,
                        'OrderingTimestamp': ordering_timestamp
                    }
                ],
                ResultToken=result_token
            )
            logger.info(f"Evaluation result: {json.dumps(evaluation_result, default=str)}")
        except Exception as e:
            logger.error(f"Error putting evaluation results: {str(e)}")
            logger.error(traceback.format_exc())
    else:
        logger.warning("No result token available, skipping put_evaluations call")

    result = {
        'compliance_type': compliance_type,
        'annotation': annotation
    }
    logger.info(f"Lambda function completed. Result: {json.dumps(result)}")
    return result
