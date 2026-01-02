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
    AWS Config rule to check if KMS encryption is enabled for individual Bedrock guardrail resources.
    Control ID: FMI-08 - bedrock-guardrails-kms-check
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
    
    # Extract configuration item from the invoking event
    configuration_item = invoking_event.get('configurationItem')
    if not configuration_item:
        logger.error("No configuration item found in invoking event")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'No configuration item found in invoking event'})
        }
    
    # Get guardrail resource details
    resource_type = configuration_item.get('resourceType')
    resource_id = configuration_item.get('resourceId')
    resource_name = configuration_item.get('resourceName', resource_id)
    
    logger.info(f"Evaluating resource: {resource_type} - {resource_id}")
    
    if resource_type != 'AWS::Bedrock::Guardrail':
        logger.error(f"Unexpected resource type: {resource_type}")
        return put_evaluation_and_return(
            config, result_token, resource_type, resource_id, 
            'NOT_APPLICABLE', f"Resource type {resource_type} is not applicable for this rule",
            invoking_event
        )
    
    try:
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock')
        
        # Check KMS encryption for the specific guardrail resource
        logger.info(f"Checking KMS encryption for guardrail: {resource_id}")
        try:
            # Get guardrail details
            guardrail_details = bedrock_client.get_guardrail(guardrailIdentifier=resource_id)
            # Log guardrail ID and KMS status only
            logger.info(f"Checking KMS encryption for guardrail: {resource_id}")
            # Check if KMS encryption is configured
            if 'kmsKeyArn' in guardrail_details:
                kms_key_id = guardrail_details['kmsKeyArn']
                logger.info(f"Guardrail {resource_id} uses KMS key: {kms_key_id}")
                
                # Check if the KMS key is in the approved list (if specified)
                if required_kms_key_ids and kms_key_id not in required_kms_key_ids:
                    compliance_type = 'NON_COMPLIANT'
                    annotation = f"Guardrail {resource_name} uses non-approved KMS key: {kms_key_id}. Approved keys: {', '.join(required_kms_key_ids)}"
                else:
                    compliance_type = 'COMPLIANT'
                    annotation = f"Guardrail {resource_name} uses KMS encryption with key: {kms_key_id}"
            else:
                compliance_type = 'NON_COMPLIANT'
                annotation = f"Guardrail {resource_name} does not have KMS encryption configured"
                logger.info(f"Guardrail {resource_id} does not use KMS encryption")
            
        except bedrock_client.exceptions.ResourceNotFoundException:
            logger.warning(f"Guardrail {resource_id} not found - may have been deleted")
            compliance_type = 'NOT_APPLICABLE'
            annotation = f"Guardrail {resource_name} not found - resource may have been deleted"
        except Exception as e:
            logger.error(f"Error checking guardrail {resource_id}: {str(e)}")
            logger.error(traceback.format_exc())
            compliance_type = 'NON_COMPLIANT'
            annotation = f"Error checking KMS encryption for guardrail {resource_name}: {str(e)}"
            
    except Exception as e:
        logger.error(f"Error evaluating Bedrock guardrail KMS encryption: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock guardrail KMS encryption: {str(e)}'
    
    return put_evaluation_and_return(
        config, result_token, resource_type, resource_id, 
        compliance_type, annotation, invoking_event
    )

def put_evaluation_and_return(config, result_token, resource_type, resource_id, compliance_type, annotation, invoking_event):
    """
    Put evaluation results to AWS Config and return the result.
    """
    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.utcnow().isoformat()
    
    # Put evaluation for the specific resource
    evaluation = {
        'ComplianceResourceType': resource_type,
        'ComplianceResourceId': resource_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': ordering_timestamp
    }
    
    if result_token:
        config.put_evaluations(
            Evaluations=[evaluation],
            ResultToken=result_token
        )
    
    logger.info(f"Evaluation result for {resource_type}/{resource_id}: {compliance_type} - {annotation}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'complianceType': compliance_type,
            'annotation': annotation,
            'resourceType': resource_type,
            'resourceId': resource_id
        })
    }