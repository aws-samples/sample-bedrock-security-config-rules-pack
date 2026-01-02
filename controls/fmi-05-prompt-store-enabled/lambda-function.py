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
    AWS Config rule to check if Bedrock prompt management is properly configured.
    Control ID: FMI-05 - bedrock-prompt-store-enabled
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

    # Get parameters
    require_versioning = rule_parameters.get('requireVersioning', 'true').lower() == 'true'
    min_prompt_count = int(rule_parameters.get('minPromptCount', '1'))
    
    logger.info(f"Require versioning: {require_versioning}")
    logger.info(f"Minimum prompt count: {min_prompt_count}")

    try:
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock-agent')
        
        # List prompts to check if prompt management is being used
        response = bedrock_client.list_prompts()
        prompts = response.get('promptSummaries', [])
        
        logger.info(f"Found {len(prompts)} prompts")
        
        if len(prompts) < min_prompt_count:
            annotation = f'Only {len(prompts)} prompts found, minimum required: {min_prompt_count}'
            logger.info(annotation)
            compliance_type = 'NON_COMPLIANT'
        else:
            # Check versioning if required
            if require_versioning:
                versioned_prompts = 0
                for prompt in prompts:
                    try:
                        # List prompt versions
                        versions_response = bedrock_client.list_prompts(
                            promptIdentifier=prompt['id']
                        )
                        
                        prompt_summaries = versions_response.get('promptSummaries', [])
                        logger.info(f"Prompt {prompt['id']} has {len(prompt_summaries)} prompt_summaries")
                        for prompt_summary in prompt_summaries:
                            version=prompt_summary['version']
                            logger.info(f"Version {version} of prompt {prompt['id']}")
                            if version != 'DRAFT':
                                versioned_prompts += 1
                                continue
                            
                    except Exception as e:
                        logger.warning(f"Error checking prompt {prompt['id']}: {str(e)}")
                
                if versioned_prompts == 0:
                    annotation = 'No versioned prompts found - prompt versioning is required'
                    logger.info(annotation)
                    compliance_type = 'NON_COMPLIANT'
                else:
                    annotation = f'Prompt store properly configured with {len(prompts)} prompts, {versioned_prompts} versioned'
                    logger.info(annotation)
                    compliance_type = 'COMPLIANT'
            else:
                annotation = f'Prompt store properly configured with {len(prompts)} prompts'
                logger.info(annotation)
                compliance_type = 'COMPLIANT'
        
    except bedrock_client.exceptions.AccessDeniedException:
        annotation = 'Access denied to Bedrock prompt management - check IAM permissions'
        logger.error(annotation)
        compliance_type = 'NON_COMPLIANT'
    except Exception as e:
        logger.error(f"Error evaluating Bedrock prompt store: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock prompt store: {str(e)}'
    
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