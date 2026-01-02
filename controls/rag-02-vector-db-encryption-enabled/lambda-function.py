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

def lambda_handler(event, context):
    """
    AWS Config rule to check if vector database encryption is enabled for individual Bedrock knowledge base resources.
    Control ID: RAG-02 - Vector Database Encryption
    
    This function validates that knowledge base vector databases use customer-managed KMS keys
    and optionally checks for specific required KMS keys.
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

    # Get rule parameters
    required_kms_key_id = rule_parameters.get('RequiredKmsKeyId', '').strip()
    allow_aws_managed_keys = rule_parameters.get('AllowAWSManagedKeys', 'false').lower() == 'true'
    
    # If required key is null/empty, make it compliant by not enforcing specific key requirement
    if not required_kms_key_id or required_kms_key_id.lower() in ['null', 'none', '']:
        required_kms_key_id = None
    
    logger.info(f"Required KMS Key ID: {required_kms_key_id}")
    logger.info(f"Allow AWS Managed Keys: {allow_aws_managed_keys}")
    
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
        
        # Check vector database encryption for the specific knowledge base
        logger.info(f"Checking knowledge base {resource_id} for vector database encryption")
        
        try:
            # Get knowledge base details
            kb_response = bedrock_client.get_knowledge_base(knowledgeBaseId=resource_id)
            kb_details = kb_response.get('knowledgeBase', {})
            
            # Check storage configuration for vector database encryption
            storage_config = kb_details.get('storageConfiguration', {})
            logger.info(f"Knowledge base {resource_id} storage configuration: {storage_config}")
            
            if not storage_config:
                compliance_type = 'NON_COMPLIANT'
                annotation = f"Knowledge base {resource_name} does not have storage configuration"
                logger.info(f"Knowledge base {resource_id} does not have storage configuration")
            else:
                # Check for vector database encryption based on AWS storage type only
                storage_type = storage_config.get('type')
                kms_key_id = None
                
                logger.info(f"Knowledge base {resource_id} storage type: {storage_type}")
                
                if storage_type == 'OPENSEARCH_SERVERLESS':
                    # For OpenSearch Serverless, check collection encryption via API
                    opensearch_config = storage_config.get('opensearchServerlessConfiguration', {})
                    logger.info(f"Knowledge base {resource_id} OpenSearch Serverless configuration: {opensearch_config}")
                    collection_arn = opensearch_config.get('collectionArn', '')
                    
                    if collection_arn:
                        try:
                            # Use OpenSearch Serverless client to get collection details
                            opensearch_serverless = boto3.client('opensearchserverless')
                            collection_name = collection_arn.split('/')[-1]
                            collection_response = opensearch_serverless.batch_get_collection(ids=[collection_name])
                            logger.info(f"Collection response: {collection_response}")
                            collections = collection_response.get('collectionDetails', [])
                            logger.info(f"Collection details: {collections}")
                            if collections:
                                for collection in collections:
                                    logger.info(f"Collection details: {collection}")
                                
                                    # Check for KMS key configuration in the collection
                                    kms_key_arn = collection.get('kmsKeyArn')
                                    
                                    if kms_key_arn:
                                        if kms_key_arn == 'auto':
                                            # AWS managed encryption
                                            kms_key_id = 'alias/aws/aoss'  # Standard AWS managed key for OpenSearch Serverless
                                            logger.info(f"OpenSearch Serverless collection uses AWS managed encryption: {kms_key_id}")
                                        else:
                                            # Customer managed key
                                            kms_key_id = kms_key_arn
                                            logger.info(f"OpenSearch Serverless collection uses customer-managed KMS key: {kms_key_id}")
                                    else:
                                        logger.info(f"OpenSearch Serverless collection does not have KMS key configuration")
                                        kms_key_id = None
                            else:
                                logger.warning(f"Could not find collection details for {collection_name}")
                                kms_key_id = None
                        except Exception as e:
                            logger.error(f"Error checking OpenSearch Serverless collection encryption: {str(e)}")
                            logger.error(traceback.format_exc())
                            kms_key_id = None
                    else:
                        logger.warning(f"No collection ARN found in OpenSearch Serverless configuration")
                        kms_key_id = None
                        # This allows the function to work even without OpenSearch Serverless permissions
                        
                elif storage_type == 'RDS':
                    # For Aurora PostgreSQL Serverless, check RDS cluster encryption
                    rds_config = storage_config.get('rdsConfiguration', {})
                    logger.info(f"Knowledge base {resource_id} RDS configuration: {rds_config}")
                    
                    resource_arn = rds_config.get('resourceArn', '')
                    if resource_arn:
                        try:
                            # Use RDS client to get cluster details
                            rds_client = boto3.client('rds')
                            # Extract cluster identifier from ARN
                            cluster_id = resource_arn.split(':')[-1]
                            cluster_response = rds_client.describe_db_clusters(DBClusterIdentifier=cluster_id)
                            clusters = cluster_response.get('DBClusters', [])
                            
                            if clusters:
                                cluster = clusters[0]
                                logger.info(f"RDS cluster details: {cluster}")
                                
                                # Check if encryption is enabled
                                storage_encrypted = cluster.get('StorageEncrypted', False)
                                if storage_encrypted:
                                    kms_key_id = cluster.get('KmsKeyId', 'alias/aws/rds')  # Default AWS managed key for RDS
                                    logger.info(f"RDS cluster uses encryption with KMS key: {kms_key_id}")
                                else:
                                    logger.info(f"RDS cluster does not have encryption enabled")
                                    kms_key_id = None
                            else:
                                logger.warning(f"Could not find RDS cluster details for {cluster_id}")
                                kms_key_id = None
                        except Exception as e:
                            logger.error(f"Error checking RDS cluster encryption: {str(e)}")
                            logger.error(traceback.format_exc())
                            kms_key_id = None
                    else:
                        logger.warning(f"No resource ARN found in RDS configuration")
                        kms_key_id = None
                        
                elif storage_type == 'S3_VECTORS':
                    logger.info("Step 9c: Processing S3_VECTORS storage type")
                    # For Amazon S3 vectors, use Bedrock's get_vector_bucket API
                    s3_vector_config = storage_config.get('s3VectorsConfiguration', {})
                    logger.info(f"S3 vectors configuration: {json.dumps(s3_vector_config, default=str, indent=2)}")
                    
                    vector_bucket_arn = s3_vector_config.get('vectorBucketArn', '')
                    index_arn = s3_vector_config.get('indexArn', '')
                    
                    # If vectorBucketArn is not available, extract bucket ARN from indexArn
                    if not vector_bucket_arn and index_arn:
                        logger.info(f"No vectorBucketArn found, extracting from indexArn: {index_arn}")
                        # Index ARN format: arn:aws:s3vectors:region:account:bucket/bucket-name/index/index-name
                        # Extract bucket ARN: arn:aws:s3vectors:region:account:bucket/bucket-name
                        try:
                            arn_parts = index_arn.split('/')
                            if len(arn_parts) >= 2:
                                # Reconstruct bucket ARN from index ARN
                                vector_bucket_arn = f"{arn_parts[0]}/{arn_parts[1]}"
                                logger.info(f"Extracted vector bucket ARN: {vector_bucket_arn}")
                            else:
                                logger.error(f"Invalid index ARN format: {index_arn}")
                        except Exception as e:
                            logger.error(f"Error extracting bucket ARN from index ARN: {str(e)}")
                    
                    logger.info(f"Final vector bucket ARN: {vector_bucket_arn}")
                    if vector_bucket_arn:
                        try:
                            logger.info("Initializing S3 Vectors client")
                            s3vectors_client = boto3.client('s3vectors')
                            # Extract bucket name from ARN for logging
                            bucket_name = vector_bucket_arn.split(':')[-1]
                            logger.info(f"Extracted vector bucket name: {bucket_name}")
                            
                            logger.info(f"Calling get_vector_bucket API for vector_bucket arn {vector_bucket_arn}")
                            vector_bucket_response = s3vectors_client.get_vector_bucket(
                                vectorBucketArn=vector_bucket_arn
                            )
                            logger.info(f"Vector bucket API response: {json.dumps(vector_bucket_response, default=str, indent=2)}")
                            
                            vector_bucket = vector_bucket_response.get('vectorBucket', {})
                            encryption_config = vector_bucket.get('encryptionConfiguration', {})
                            logger.info(f"Vector bucket encryption configuration: {json.dumps(encryption_config, default=str, indent=2)}")
                            
                            if encryption_config:
                                sse_type = encryption_config.get('sseType', '')
                                logger.info(f"Vector bucket SSE type: {sse_type}")
                                
                                if sse_type == 'aws:kms':
                                    kms_key_id = encryption_config.get('kmsKeyArn', 'alias/aws/s3')
                                    logger.info(f"Vector bucket uses KMS encryption with key: {kms_key_id}")
                                elif sse_type == 'AES256':
                                    kms_key_id = 'alias/aws/s3'  # S3 managed encryption
                                    logger.info(f"Vector bucket uses S3 managed encryption (AES256)")
                                else:
                                    logger.warning(f"Vector bucket has unknown SSE type: {sse_type}")
                                    kms_key_id = None
                            else:
                                logger.warning(f"Vector bucket does not have encryption configuration")
                                kms_key_id = None
                                
                        except s3vectors_client.exceptions.NotFoundException:
                            logger.warning(f"Vector bucket {bucket_name} not found")
                            kms_key_id = None
                        except Exception as e:
                            logger.error(f"Error checking vector bucket encryption: {str(e)}")
                            logger.error(traceback.format_exc())
                            kms_key_id = None
                    else:
                        logger.warning(f"No vector bucket ARN found in S3 vectors configuration")
                        kms_key_id = None
                        
                else:
                    # Non-AWS storage types are not supported by this control
                    logger.warning(f"Storage type {storage_type} is not an AWS-managed storage type")
                    compliance_type = 'NOT_APPLICABLE'
                    annotation = f"Knowledge base {resource_name} uses non-AWS storage type {storage_type} - control only applies to AWS storage types (OPENSEARCH_SERVERLESS, RDS, S3_VECTORS)"
                    return put_evaluation_and_return(config, result_token, resource_type, resource_id, compliance_type, annotation, invoking_event)

                
                if not kms_key_id:
                    logger.info("No KMS key found - evaluating based on AWS managed key policy")
                    if allow_aws_managed_keys:
                        # If AWS managed keys are allowed, we still need some form of encryption
                        compliance_type = 'NON_COMPLIANT'
                        annotation = f"Knowledge base {resource_name} vector database does not have encryption configuration"
                        logger.info("No encryption found - NON_COMPLIANT")
                    else:
                        compliance_type = 'NON_COMPLIANT'
                        annotation = f"Knowledge base {resource_name} vector database does not use customer-managed KMS key"
                        logger.info("No customer-managed key found - NON_COMPLIANT")
                else:
                    logger.info("KMS key found - analyzing key type and compliance")
                    # Check if it's an AWS managed key
                    is_aws_managed = (
                        kms_key_id.startswith('alias/aws/') or 
                        (kms_key_id.startswith('arn:aws:kms:') and ':key/aws/' in kms_key_id)
                    )
                    logger.info(f"Is AWS managed key: {is_aws_managed}")
                    
                    if is_aws_managed and not allow_aws_managed_keys:
                        logger.info("AWS managed key found but not allowed - NON_COMPLIANT")
                        compliance_type = 'NON_COMPLIANT'
                        annotation = f"Knowledge base {resource_name} vector database uses AWS managed key {kms_key_id} but customer-managed key is required"
                    elif required_kms_key_id is not None and kms_key_id != required_kms_key_id:
                        logger.info(f"Specific key required but different key found - NON_COMPLIANT")
                        compliance_type = 'NON_COMPLIANT'
                        annotation = f"Knowledge base {resource_name} vector database uses KMS key {kms_key_id} but required key is {required_kms_key_id}"
                    else:
                        logger.info("All compliance checks passed - COMPLIANT")
                        compliance_type = 'COMPLIANT'
                        key_type = "AWS managed" if is_aws_managed else "customer-managed"
                        annotation = f"Knowledge base {resource_name} vector database uses {key_type} KMS key: {kms_key_id}"
                    
           
                
        except bedrock_client.exceptions.ResourceNotFoundException:
            logger.warning(f"Knowledge base {resource_id} not found - may have been deleted")
            compliance_type = 'NOT_APPLICABLE'
            annotation = f"Knowledge base {resource_name} not found - resource may have been deleted"
        except Exception as e:
            logger.error(f"Error checking knowledge base {resource_id}: {str(e)}")
            logger.error(traceback.format_exc())
            compliance_type = 'NON_COMPLIANT'
            annotation = f"Error checking knowledge base {resource_name} vector database encryption: {str(e)}"
            
    except Exception as e:
        logger.error(f"Error evaluating Bedrock knowledge base vector database encryption: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock knowledge base vector database encryption: {str(e)}'
    
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