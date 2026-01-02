import boto3
import json
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

bedrock = boto3.client('bedrock')
bedrock_agent = boto3.client('bedrock-agent')
sns = boto3.client('sns')

def handler(event, context):
    """
    Remediation function for RAG-01 - Knowledge Base Data Source Validation
    Removes unauthorized data sources and sends notifications
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Get parameters from event payload
    required_tags = event.get('requiredTags', '')
    notification_topic_arn = event.get('notificationTopicArn', '')
    auto_remove = event.get('autoRemove', 'false').lower() == 'true'
    resource_id = event.get('resourceId', '')
    
    # Parse required tags
    required_tag_dict = {}
    if required_tags:
        for tag in required_tags.split(','):
            if '=' in tag:
                key, value = tag.split('=', 1)
                required_tag_dict[key.strip()] = value.strip()
    
    logger.info(f"Required tags: {required_tag_dict}")
    logger.info(f"Auto remove: {auto_remove}")
    logger.info(f"Resource ID: {resource_id}")
    logger.info(f"Notification topic ARN: {notification_topic_arn}")
    
    try:
        if not resource_id:
            error_msg = 'Resource ID is required for remediation'
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Process specific knowledge base
        kb_id = resource_id
        kb_details = bedrock_agent.get_knowledge_base(knowledgeBaseId=kb_id)
        logger.info(f"Processing knowledge base: {kb_details}")
        kb_name = kb_details['knowledgeBase']['name']
        logger.info(f"Processing knowledge base: {kb_name}")

        violations = []
        remediated_sources = []
            
        # Get data sources for this knowledge base
        ds_response = bedrock_agent.list_data_sources(knowledgeBaseId=kb_id)   
        data_sources = ds_response.get('dataSourceSummaries', [])
        logger.info(f"Data sources: {data_sources}")
        for ds in data_sources:
            ds_id = ds['dataSourceId']
            ds_name = ds['name']
            
            # Get data source details
            ds_details = bedrock_agent.get_data_source(
                knowledgeBaseId=kb_id,
                dataSourceId=ds_id
            )
            ds_config = ds_details['dataSource']['dataSourceConfiguration']
            
            # Check S3 data sources
            if 's3Configuration' in ds_config:
                s3_config = ds_config['s3Configuration']
                bucket_arn = s3_config.get('bucketArn', '')
                bucket_name = bucket_arn.split(':::')[-1] if bucket_arn else ''
                
                if bucket_name and required_tag_dict:
                    # Check if bucket has required tags
                    if not has_required_tags(bucket_name, required_tag_dict):
                        violation = {
                            'knowledge_base': kb_name,
                            'data_source': ds_name,
                            'bucket': bucket_name,
                            'kb_id': kb_id,
                            'ds_id': ds_id
                        }
                        logger.info(f"Unauthorized data source found: {json.dumps(violation)}")
                        violations.append(violation)
                        
                        # Remove data source if auto-remove is enabled
                        if auto_remove:
                            logger.info(f"Removing unauthorized data source: {ds_name}")
                            try:
                                bedrock_agent.delete_data_source(
                                    knowledgeBaseId=kb_id,
                                    dataSourceId=ds_id
                                )
                                remediated_sources.append(f"{kb_name}/{ds_name}")
                                logger.info(f"Removed unauthorized data source: {ds_name} from {kb_name}")
                            except Exception as e:
                                logger.error(f"Failed to remove data source {ds_name}: {str(e)}")
        
        # Send notification if violations found and valid topic provided
        if violations and notification_topic_arn and notification_topic_arn.lower() not in ['null', 'none', '']:
            logger.info(f"Sending notification for {len(violations)} violations to topic: {notification_topic_arn}")
            send_notification(notification_topic_arn, violations, remediated_sources, auto_remove)
        elif violations:
            logger.info(f"Found {len(violations)} violations but no valid notification topic configured (topic_arn: '{notification_topic_arn}')")        
        result = {
            'statusCode': 200,
            'violations_found': len(violations),
            'remediated_sources': remediated_sources,
            'message': f"Knowledge base {kb_name}: Found {len(violations)} violations, remediated {len(remediated_sources)} sources"
        }
        
        logger.info(f"Remediation completed: {json.dumps(result)}")
        return result
        
    except Exception as e:
        logger.error(f"Error in remediation: {str(e)}")
        return {
            'statusCode': 500,
            'message': f"Error in remediation: {str(e)}"
        }

def has_required_tags(bucket_name, required_tag_dict):
    """Check if S3 bucket has all required tags"""
    try:
        s3 = boto3.client('s3')
        tag_response = s3.get_bucket_tagging(Bucket=bucket_name)
        bucket_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
        
        for req_key, req_value in required_tag_dict.items():
            if req_key not in bucket_tags or bucket_tags[req_key] != req_value:
                return False
        return True
    except ClientError:
        return False

def send_notification(topic_arn, violations, remediated_sources, auto_remove):
    """Send SNS notification about violations"""
    try:
        action_taken = "automatically removed" if auto_remove else "require manual review"
        
        message = f"""
RAG-01 Knowledge Base Data Source Validation Alert

Found {len(violations)} knowledge base data sources with unauthorized S3 buckets.

Violations:
"""
        for v in violations[:10]:  # Limit to first 10 violations
            message += f"- Knowledge Base: {v['knowledge_base']}, Data Source: {v['data_source']}, Bucket: {v['bucket']}\n"
        
        if len(violations) > 10:
            message += f"... and {len(violations) - 10} more violations\n"
        
        if remediated_sources:
            message += f"\nRemediated Sources:\n"
            for source in remediated_sources:
                message += f"- {source}\n"
        
        message += f"\nAction: Unauthorized data sources {action_taken}."
        
        sns.publish(
            TopicArn=topic_arn,
            Subject="RAG-01 Knowledge Base Data Source Violations",
            Message=message
        )
        logger.info("Notification sent successfully")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")