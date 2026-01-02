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
    AWS Lambda function to remediate non-compliant Bedrock knowledge base data source KMS encryption.
    This function updates data sources within knowledge bases to use customer-managed KMS keys.
    """
    logger.info("Starting remediation for Bedrock knowledge base data source KMS encryption")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Parse event data
    try:
        # Extract parameters from the event payload (consistent with other controls)
        resource_id = event.get('resourceId')
        kms_key_id = event.get('kmsKeyId')
    
        logger.info(f"Resource ID: {resource_id}")
        logger.info(f"KMS Key ID: {kms_key_id}")
        
        if not resource_id:
            logger.error("No Resource ID provided")
            return {
                'statusCode': 400,
                'message': "Resource ID is required for remediation"
            }
            
        if not kms_key_id:
            logger.error("No KMS Key ID provided")
            return {
                'statusCode': 400,
                'message': "KMS Key ID is required for remediation"
            }
        
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock-agent')
        
        # Check the knowledge base data sources for KMS encryption and remediate
        try:
            kb_details = bedrock_client.get_knowledge_base(knowledgeBaseId=resource_id)
            kb_name = kb_details.get('knowledgeBase', {}).get('name', resource_id)
            
            logger.info(f"Checking knowledge base {resource_id} ({kb_name}) data sources for KMS encryption")
            
            # Get data sources for the knowledge base
            data_sources_response = bedrock_client.list_data_sources(knowledgeBaseId=resource_id)
            data_sources = data_sources_response.get('dataSourceSummaries', [])
            
            logger.info(f"Found {len(data_sources)} data sources for knowledge base {resource_id}")
            
            if not data_sources:
                return {
                    'statusCode': 200,
                    'message': f"Knowledge base {kb_name} has no data sources to evaluate for KMS encryption",
                    'resourceId': resource_id,
                    'knowledgeBaseName': kb_name,
                    'dataSourcesCount': 0,
                    'compliant': True
                }
            
            # Track remediation results
            remediated_sources = []
            failed_sources = []
            already_compliant_sources = []
            warning_sources = []
            
            # Process each data source
            for data_source in data_sources:
                data_source_id = data_source['dataSourceId']
                data_source_name = data_source.get('name', data_source_id)
                
                try:
                    # Get detailed data source information
                    ds_details = bedrock_client.get_data_source(
                        knowledgeBaseId=resource_id,
                        dataSourceId=data_source_id
                    )
                    
                    logger.info(f"Processing data source {data_source_id} ({data_source_name})")
                    
                    # Extract the actual data source details
                    data_source_info = ds_details['dataSource']
                    
                    # Check current encryption configuration
                    current_kms_key = None
                    has_encryption = False
                    needs_update = False
                    
                    if 'serverSideEncryptionConfiguration' in data_source_info:
                        encryption_config = data_source_info['serverSideEncryptionConfiguration']
                        if 'kmsKeyArn' in encryption_config:
                            has_encryption = True
                            current_kms_arn = encryption_config['kmsKeyArn']
                            current_kms_key = current_kms_arn.split('/')[-1] if '/' in current_kms_arn else current_kms_arn
                            
                            # Check if already using the required key
                            if current_kms_key == kms_key_id:
                                already_compliant_sources.append(f"{data_source_name} (already using {kms_key_id})")
                                logger.info(f"Data source {data_source_id} already uses required KMS key")
                            else:
                                # KMS key exists but doesn't match - add warning, don't update
                                warning_sources.append(f"{data_source_name} (using non-matching key: {current_kms_key})")
                                logger.warning(f"Data source {data_source_id} uses non-matching KMS key {current_kms_key}, expected {kms_key_id}")
                        else:
                            # Has encryption config but no KMS key - needs update
                            needs_update = True
                    else:
                        # No encryption configuration at all - needs update
                        needs_update = True
                    
                    if needs_update:
                        # Only update if KMS key is missing entirely
                        logger.info(f"Updating data source {data_source_id} with KMS key {kms_key_id} (missing encryption)")
                        #if kms_key_id is not in arn format Build KMS ARN else use kms_key_id as kms_key_arn
                        if not kms_key_id.startswith('arn:aws:kms:'):
                            kms_key_arn = f"arn:aws:kms:{boto3.Session().region_name}:{boto3.client('sts').get_caller_identity()['Account']}:key/{kms_key_id}"
                        else:
                            kms_key_arn = kms_key_id
                        
                        # Update the data source using correct API syntax
                        update_params = {
                            'knowledgeBaseId': resource_id,
                            'dataSourceId': data_source_id,
                            'name': data_source_info.get('name', data_source_name),
                            'dataSourceConfiguration': data_source_info['dataSourceConfiguration'],
                            'serverSideEncryptionConfiguration': {
                                'kmsKeyArn': kms_key_arn
                            }
                        }
                        
                        # Add description only if it exists and is not empty
                        if data_source_info.get('description'):
                            update_params['description'] = data_source_info['description']
                        
                        response = bedrock_client.update_data_source(**update_params)
                        
                        remediated_sources.append(f"{data_source_name} (added KMS key {kms_key_id})")
                        logger.info(f"Successfully updated data source {data_source_id}")
                        
                except Exception as e:
                    logger.error(f"Error updating data source {data_source_id}: {str(e)}")
                    logger.error(traceback.format_exc())
                    failed_sources.append(f"{data_source_name} (error: {str(e)})")
            
            # Prepare response
            total_sources = len(data_sources)
            remediated_count = len(remediated_sources)
            failed_count = len(failed_sources)
            compliant_count = len(already_compliant_sources)
            warning_count = len(warning_sources)
            
            success_rate = (remediated_count + compliant_count) / total_sources if total_sources > 0 else 0
            
            # Build message based on data source remediation results
            message_parts = []
            if remediated_count > 0:
                message_parts.append(f"{remediated_count} data sources updated with KMS encryption")
            if compliant_count > 0:
                message_parts.append(f"{compliant_count} data sources already compliant")
            if warning_count > 0:
                message_parts.append(f"{warning_count} data sources with non-matching keys (warnings)")
            if failed_count > 0:
                message_parts.append(f"{failed_count} data sources failed")
            
            if failed_count == 0 and warning_count == 0:
                status_code = 200
                message = f"Successfully remediated knowledge base data sources for {kb_name}. {', '.join(message_parts)}"
            elif failed_count == 0:
                status_code = 200
                message = f"Data source remediation completed with warnings for knowledge base {kb_name}. {', '.join(message_parts)}"
            else:
                status_code = 207  # Multi-status
                message = f"Partial data source remediation for knowledge base {kb_name}. {', '.join(message_parts)}"
            
            return {
                'statusCode': status_code,
                'message': message,
                'resourceId': resource_id,
                'knowledgeBaseName': kb_name,
                'requiredKmsKey': kms_key_id,
                'totalDataSources': total_sources,
                'remediatedSources': remediated_count,
                'alreadyCompliantSources': compliant_count,
                'warningSources': warning_count,
                'failedSources': failed_count,
                'successRate': f"{success_rate:.2%}",
                'details': {
                    'remediated': remediated_sources,
                    'alreadyCompliant': already_compliant_sources,
                    'warnings': warning_sources,
                    'failed': failed_sources
                },
                'compliant': failed_count == 0 and warning_count == 0
            }
            
        except bedrock_client.exceptions.ResourceNotFoundException:
            logger.warning(f"Knowledge base {resource_id} not found - may have been deleted")
            return {
                'statusCode': 404,
                'message': f"Knowledge base {resource_id} not found - resource may have been deleted",
                'resourceId': resource_id
            }
        except Exception as e:
            logger.error(f"Error checking knowledge base data sources {resource_id}: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'statusCode': 500,
                'message': f"Error checking knowledge base data sources {resource_id}: {str(e)}",
                'resourceId': resource_id
            }
        
    except Exception as e:
        logger.error(f"Error remediating Bedrock knowledge base data source KMS encryption: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'message': f"Error remediating Bedrock knowledge base data source KMS encryption: {str(e)}"
        }