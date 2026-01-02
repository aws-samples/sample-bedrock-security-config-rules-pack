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
    AWS Lambda function to remediate Bedrock guardrail KMS encryption.
    Adds KMS encryption if missing, warns if different key already exists.
    """
    logger.info("Starting remediation for Bedrock guardrail KMS encryption")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    # Parse event data
    try:
        guardrail_id = None
        kms_key_id = None
        
        # For direct Lambda invocation
        if 'guardrailId' in event:
            guardrail_id = event['guardrailId']
            kms_key_id = event.get('kmsKeyId')
            
        # For SSM Automation Document invocation
        elif 'ResourceId' in event:
            guardrail_id = event['ResourceId']
            kms_key_id = event.get('KmsKeyId')
            
        # For AWS Config Remediation
        elif 'configurationItem' in event:
            configuration_item = event['configurationItem']
            guardrail_id = configuration_item.get('resourceId')
            kms_key_id = event.get('kmsKeyId')
            
        logger.info("Guardrail ID: %s", guardrail_id)
        logger.info("KMS Key ID: %s", kms_key_id)
        
        if not guardrail_id:
            return {
                'statusCode': 400,
                'message': "Guardrail ID is required for remediation"
            }
        
        if not kms_key_id:
            return {
                'statusCode': 400,
                'message': "KMS Key ID is required for remediation"
            }
        
        # Initialize Bedrock client
        bedrock_client = boto3.client('bedrock')
        
        # Check current guardrail status
        try:
            guardrail_details = bedrock_client.get_guardrail(guardrailIdentifier=guardrail_id)
            logger.info(f"Guardrail details for {guardrail_id} : {json.dumps(guardrail_details, default=str)}")
            
            # Check KMS key status
            current_kms_key = guardrail_details.get('kmsKeyId')
            guardrail_name = guardrail_details.get('name', guardrail_id)
            
            if current_kms_key == kms_key_id:
                return {
                    'statusCode': 200,
                    'message': f"Guardrail {guardrail_name} is already compliant with KMS key {kms_key_id}",
                    'guardrailId': guardrail_id,
                    'compliant': True
                }
            elif current_kms_key:
                # Different KMS key - log warning but don't update
                logger.warning(f"Guardrail {guardrail_name} uses different KMS key: {current_kms_key} (expected: {kms_key_id})")
                return {
                    'statusCode': 200,
                    'message': f"WARNING: Guardrail {guardrail_name} uses different KMS key ({current_kms_key}) than expected ({kms_key_id})",
                    'guardrailId': guardrail_id,
                    'currentKmsKey': current_kms_key,
                    'expectedKmsKey': kms_key_id,
                    'compliant': False,
                    'warning': True
                }
            else:
                # No KMS key - remediate by adding it
                logger.info(f"Guardrail {guardrail_name} missing KMS encryption, adding key {kms_key_id}")
                
                # Format KMS key ID to ARN if needed
                if not kms_key_id.startswith('arn:aws:kms:') and not kms_key_id.startswith('alias/'):
                    region = context.invoked_function_arn.split(':')[3]
                    account_id = context.invoked_function_arn.split(':')[4]
                    kms_key_arn = f"arn:aws:kms:{region}:{account_id}:key/{kms_key_id}"
                else:
                    kms_key_arn = kms_key_id
                
                # Copy guardrail config and add KMS key
                update_params = guardrail_details.copy()
                update_params['guardrailIdentifier'] = guardrail_id
                update_params['kmsKeyId'] = kms_key_arn
                
                # Remove fields that update API doesn't accept
                fields_to_remove = ['guardrailId', 'guardrailArn', 'version', 'status', 'statusReasons', 
                                  'createdAt', 'updatedAt', 'failureRecommendations', 'ResponseMetadata', 'kmsKeyArn']
                for field in fields_to_remove:
                    update_params.pop(field, None)
                
                logger.info(f"Guardrail {guardrail_name} update params: {json.dumps(update_params, default=str)}")
                # Rename policy fields from get_guardrail response to update_guardrail format
                policy_mappings = {
                    'topicPolicy': 'topicPolicyConfig',
                    'contentPolicy': 'contentPolicyConfig', 
                    'wordPolicy': 'wordPolicyConfig',
                    'sensitiveInformationPolicy': 'sensitiveInformationPolicyConfig',
                    'contextualGroundingPolicy': 'contextualGroundingPolicyConfig'
                }
                
                for old_name, new_name in policy_mappings.items():
                    if old_name in update_params:
                        policy_config = update_params.pop(old_name)
                        logger.info(f"Guardrail {guardrail_name} policy config: {json.dumps(policy_config, default=str)}")
                        # Rename nested fields within each policy config
                        if old_name == 'topicPolicy' and policy_config:
                            if 'topics' in policy_config:
                                topics_config = policy_config.pop('topics')
                                # Only include topicsConfig if it has items (API requires min length 1)
                                if topics_config:
                                    policy_config['topicsConfig'] = topics_config
                            if 'tier' in policy_config:
                                policy_config['tierConfig'] = policy_config.pop('tier')
                        
                        elif old_name == 'contentPolicy' and policy_config:
                            if 'filters' in policy_config:
                                filters_config = policy_config.pop('filters')
                                # Only include filtersConfig if it has items (API requires min length 1)
                                if filters_config:
                                    policy_config['filtersConfig'] = filters_config
                            if 'tier' in policy_config:
                                policy_config['tierConfig'] = policy_config.pop('tier')
                        
                        elif old_name == 'wordPolicy' and policy_config:
                            if 'words' in policy_config:
                                words_config = policy_config.pop('words')
                                # Only include wordsConfig if it has items (API requires min length 1)
                                if words_config:
                                    policy_config['wordsConfig'] = words_config
                            if 'managedWordLists' in policy_config:
                                managed_word_lists_config = policy_config.pop('managedWordLists')
                                # Only include managedWordListsConfig if it has items (API requires min length 1)
                                if managed_word_lists_config:
                                    policy_config['managedWordListsConfig'] = managed_word_lists_config
                        
                        elif old_name == 'sensitiveInformationPolicy' and policy_config:
                            if 'piiEntities' in policy_config:
                                pii_entities_config = policy_config.pop('piiEntities')
                                # Only include piiEntitiesConfig if it has items (API requires min length 1)
                                if pii_entities_config:
                                    policy_config['piiEntitiesConfig'] = pii_entities_config
                            if 'regexes' in policy_config:
                                regexes_config = policy_config.pop('regexes')
                                # Only include regexesConfig if it has items (API requires min length 1)
                                if regexes_config:
                                    policy_config['regexesConfig'] = regexes_config
                        
                        update_params[new_name] = policy_config
                
                logger.info(f"Updating guardrail {guardrail_name} with KMS key {kms_key_arn}")
                logger.info(f"Update params: {json.dumps(update_params, default=str)}")

                response = bedrock_client.update_guardrail(**update_params)
                
                logger.info(f"Successfully updated guardrail {guardrail_name} with KMS encryption")
                
                return {
                    'statusCode': 200,
                    'message': f"Successfully added KMS encryption to guardrail {guardrail_name}",
                    'guardrailId': guardrail_id,
                    'guardrailArn': response.get('guardrailArn'),
                    'version': response.get('version'),
                    'kmsKeyId': kms_key_arn,
                    'remediated': True
                }
            
        except bedrock_client.exceptions.ResourceNotFoundException:
            return {
                'statusCode': 404,
                'message': f"Guardrail {guardrail_id} not found",
                'guardrailId': guardrail_id,
                'remediated': False
            }
            
        except Exception as e:
            logger.error(f"Error checking guardrail: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'statusCode': 500,
                'message': f"Error checking guardrail KMS encryption: {str(e)}",
                'guardrailId': guardrail_id,
                'compliant': False
            }
        
    except Exception as e:
        logger.error(f"Error in remediation: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            'statusCode': 500,
            'message': f"Error in remediation: {str(e)}"
        }