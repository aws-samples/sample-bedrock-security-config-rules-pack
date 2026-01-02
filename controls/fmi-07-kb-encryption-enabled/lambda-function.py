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
    AWS Config rule to check if KMS encryption is enabled for Bedrock knowledge base data sources.
    Control ID: FMI-07 - bedrock-knowledge-bases-kms-check
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
    
    # Get knowledge base details from configuration item
    resource_type = configuration_item.get('resourceType')
    resource_id = configuration_item.get('resourceId')
    resource_name = configuration_item.get('resourceName', resource_id)
    
    logger.info(f"Evaluating resource: {resource_type} - {resource_id}")
    
    # Validate resource type
    if resource_type != 'AWS::Bedrock::KnowledgeBase':
        logger.error(f"Unexpected resource type: {resource_type}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Unexpected resource type: {resource_type}'})
        }
    
    try:
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock-agent')
        
        # Check for KMS encryption in the knowledge base data sources
        logger.info(f"Checking knowledge base {resource_id} data sources for KMS encryption")
        
        try:
            # Get knowledge base details
            kb_details = bedrock_client.get_knowledge_base(knowledgeBaseId=resource_id)
            logger.info(f"Knowledge base {resource_id} details: {json.dumps(kb_details, default=str)}")

            # Get data sources for the knowledge base to check encryption
            data_sources_response = bedrock_client.list_data_sources(knowledgeBaseId=resource_id)
            data_sources = data_sources_response.get('dataSourceSummaries', [])
            
            logger.info(f"Found {len(data_sources)} data sources for knowledge base {resource_id}")
            
            if not data_sources:
                compliance_type = 'NOT_APPLICABLE'
                annotation = "No data sources found in knowledge base to evaluate for KMS encryption"
            else:
                # Check encryption for each data source
                all_compliant = True  # Start optimistic, set to False if any issues found
                non_compliant_sources = []
                compliant_sources = []
                
                for data_source in data_sources:
                    data_source_id = data_source['dataSourceId']
                    data_source_name = data_source.get('name', data_source_id)
                    
                    try:
                        # Get detailed data source information
                        ds_details = bedrock_client.get_data_source(
                            knowledgeBaseId=resource_id,
                            dataSourceId=data_source_id
                        ).get('dataSource', {})
                        
                        logger.info(f"Data source {data_source_id} details: {json.dumps(ds_details, default=str)}")
                        
                        # Check encryption configuration in data source
                        if 'serverSideEncryptionConfiguration' in ds_details:
                            encryption_config = ds_details['serverSideEncryptionConfiguration']
                            if 'kmsKeyArn' in encryption_config:
                                kms_key_arn = encryption_config['kmsKeyArn']
                                logger.info(f"Data source {data_source_id} uses KMS key: {kms_key_arn}")
                                
                                # Extract KMS key ID from ARN (format: arn:aws:kms:region:account:key/key-id)
                                kms_key_id = kms_key_arn.split('/')[-1] if '/' in kms_key_arn else kms_key_arn
                                logger.info(f"Extracted KMS key ID: {kms_key_id}")
                                
                                # Check if the KMS key ID is in the required list (if specified)
                                if required_kms_key_ids and kms_key_id not in required_kms_key_ids:
                                    all_compliant = False
                                    non_compliant_sources.append(f"{data_source_name} (non-approved key: {kms_key_id})")
                                else:
                                    compliant_sources.append(f"{data_source_name} (key: {kms_key_id})")
                            else:
                                all_compliant = False
                                non_compliant_sources.append(f"{data_source_name} (no KMS key specified)")
                        else:
                            all_compliant = False
                            non_compliant_sources.append(f"{data_source_name} (no encryption configuration)")
                            
                    except Exception as e:
                        logger.error(f"Error checking data source {data_source_id}: {str(e)}")
                        all_compliant = False
                        non_compliant_sources.append(f"{data_source_name} (error: {str(e)})")
                
                # Determine overall compliance for knowledge base data sources
                if all_compliant:
                    compliance_type = 'COMPLIANT'
                    annotation = f"All {len(data_sources)} knowledge base data sources use customer-managed KMS encryption"
                else:
                    compliance_type = 'NON_COMPLIANT'
                    compliant_count = len(compliant_sources)
                    non_compliant_count = len(non_compliant_sources)
                    annotation = f"{non_compliant_count} of {len(data_sources)} knowledge base data sources lack proper KMS encryption"
                    if compliant_count > 0:
                        annotation += f" ({compliant_count} compliant)"
                
        except bedrock_client.exceptions.ResourceNotFoundException:
            logger.warning(f"Knowledge base {resource_id} not found - may have been deleted")
            compliance_type = 'NOT_APPLICABLE'
            annotation = "Knowledge base not found - may have been deleted"
        except Exception as e:
            logger.error(f"Error checking knowledge base {resource_id}: {str(e)}")
            logger.error(traceback.format_exc())
            compliance_type = 'NON_COMPLIANT'
            annotation = f"Error checking encryption: {str(e)[:100]}..."
            
    except Exception as e:
        logger.error(f"Error evaluating Bedrock knowledge base data source KMS encryption: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock knowledge base data source KMS encryption: {str(e)}'
    
    return put_evaluation_and_return(config, result_token, resource_type, resource_id, compliance_type, annotation, invoking_event)

def put_evaluation_and_return(config, result_token, resource_type, resource_id, compliance_type, annotation, invoking_event):
    """
    Put evaluation results to AWS Config and return the result.
    """
    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.utcnow().isoformat()
    
    # Put evaluation for the specific knowledge base resource
    evaluation = {
        'ComplianceResourceType': resource_type,
        'ComplianceResourceId': resource_id,
        'ComplianceType': compliance_type,
        'Annotation': annotation,
        'OrderingTimestamp': ordering_timestamp
    }
    
    if result_token:
        try:
            config.put_evaluations(
                Evaluations=[evaluation],
                ResultToken=result_token
            )
            logger.info(f"Successfully submitted evaluation for resource {resource_id}")
        except Exception as e:
            logger.error(f"Error submitting evaluation: {str(e)}")
            logger.error(traceback.format_exc())
    
    logger.info(f"Evaluation result for {resource_id}: {compliance_type} - {annotation}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'resourceId': resource_id,
            'resourceType': resource_type,
            'complianceType': compliance_type,
            'annotation': annotation
        })
    }