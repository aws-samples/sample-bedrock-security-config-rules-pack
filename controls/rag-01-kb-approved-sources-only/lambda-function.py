import boto3
import json
import datetime
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
config = boto3.client('config')
bedrock = boto3.client('bedrock')
bedrock_agent = boto3.client('bedrock-agent')
s3 = boto3.client('s3')

def handler(event, context):
    """
    AWS Config rule to check if knowledge bases use only approved data sources.
    Control ID: RAG-01 - Knowledge Base Data Source Validation
    """
    logger.info("Lambda function invoked")
    logger.info(f"Event: {json.dumps(event, default=str)}")

    # Parse the event
    try:
        invoking_event = json.loads(event.get('invokingEvent', '{}'))
        logger.info(f"Invoking event parsed: {json.dumps(invoking_event, default=str)}")
    except Exception as e:
        logger.error(f"Error parsing invokingEvent: {str(e)}")
        invoking_event = {}

    # Get configuration item
    configuration_item = invoking_event.get('configurationItem', {})
    resource_type = configuration_item.get('resourceType')
    resource_id = configuration_item.get('resourceId')
    
    # Get account ID
    account_id = event.get('accountId')
    if not account_id:
        account_id = context.invoked_function_arn.split(':')[4]
    logger.info(f"Account ID: {account_id}")

    # Get result token
    result_token = event.get('resultToken')

    # Get rule parameters
    rule_parameters = json.loads(event.get('ruleParameters', '{}'))
    required_tags = rule_parameters.get('RequiredTags', '').split(',') if rule_parameters.get('RequiredTags') else []
    approved_types = rule_parameters.get('ApprovedDataSourceTypes', 'S3').split(',')
    allowed_regions = rule_parameters.get('AllowedRegions', '').split(',') if rule_parameters.get('AllowedRegions') else []

    # Validate that required tags are provided
    if not required_tags or not any(required_tags):
        compliance_type = 'NON_COMPLIANT'
        annotation = 'RequiredTags parameter must be specified for data source validation'
        result = {'compliance_type': compliance_type, 'annotation': annotation}
        logger.error(f"Lambda function completed with error. Result: {json.dumps(result)}")
        return result
    
    # Parse required tags into key-value pairs
    required_tag_dict = {}
    for tag in required_tags:
        if '=' in tag:
            key, value = tag.split('=', 1)
            required_tag_dict[key.strip()] = value.strip()

    logger.info(f"Required tags: {required_tag_dict}")
    logger.info(f"Approved types: {approved_types}")
    logger.info(f"Allowed regions: {allowed_regions}")

    try:
        # Check if we have a specific knowledge base to evaluate
        if not resource_id:
            compliance_type = 'NOT_APPLICABLE'
            annotation = 'No knowledge base resource specified for evaluation.'
        else:
            kb_id = resource_id
            logger.info(f"Evaluating knowledge base: {kb_id}")
            
            # Get knowledge base details
            kb_details = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
            kb_name = kb_details['knowledgeBase']['name']
            
            # Get data sources for this knowledge base
            ds_response = bedrock_agent.list_data_sources(knowledgeBaseId=kb_id)
            data_sources = ds_response.get('dataSourceSummaries', [])
            
            violations = []
            
            for ds in data_sources:
                ds_id = ds['dataSourceId']
                
                # Get data source details
                ds_details = bedrock_agent.get_data_source(
                    knowledgeBaseId=kb_id,
                    dataSourceId=ds_id
                )
                ds_config = ds_details['dataSource']['dataSourceConfiguration']
                
                # Check data source type
                if 's3Configuration' in ds_config:
                    if 'S3' not in approved_types:
                        violations.append(f"Unapproved data source type S3")
                        continue
                        
                    s3_config = ds_config['s3Configuration']
                    bucket_arn = s3_config.get('bucketArn', '')
                    bucket_name = bucket_arn.split(':::')[-1] if bucket_arn else ''
                    
                    # Check bucket tags
                    if bucket_name:
                        try:
                            tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
                            bucket_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                            
                            # Check if all required tags are present with correct values
                            missing_tags = []
                            for req_key, req_value in required_tag_dict.items():
                                if req_key not in bucket_tags or bucket_tags[req_key] != req_value:
                                    missing_tags.append(f"{req_key}={req_value}")
                            
                            if missing_tags:
                                violations.append(f"S3 bucket {bucket_name} missing required tags: {', '.join(missing_tags)}")
                        except Exception as e:
                            logger.warning(f"Could not get tags for bucket {bucket_name}: {str(e)}")
                            violations.append(f"Could not validate tags for S3 bucket {bucket_name}")
            
            if violations:
                compliance_type = 'NON_COMPLIANT'
                annotation = f"Knowledge base {kb_name} violations: {'; '.join(violations[:3])}"
                if len(violations) > 3:
                    annotation += f" and {len(violations) - 3} more"
            else:
                compliance_type = 'COMPLIANT'
                annotation = f"Knowledge base {kb_name} uses approved data sources."

    except Exception as e:
        logger.error(f"Error checking knowledge base data sources: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error checking knowledge base data sources: {str(e)}'

    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.datetime.utcnow().isoformat()

    # Put evaluation results
    if result_token:
        try:
            config.put_evaluations(
                Evaluations=[
                    {
                        'ComplianceResourceType': resource_type or 'AWS::Bedrock::KnowledgeBase',
                        'ComplianceResourceId': resource_id or account_id,
                        'ComplianceType': compliance_type,
                        'Annotation': annotation,
                        'OrderingTimestamp': ordering_timestamp
                    }
                ],
                ResultToken=result_token
            )
        except Exception as e:
            logger.error(f"Error putting evaluation results: {str(e)}")

    result = {
        'compliance_type': compliance_type,
        'annotation': annotation
    }
    logger.info(f"Lambda function completed. Result: {json.dumps(result)}")
    return result