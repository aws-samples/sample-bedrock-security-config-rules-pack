import boto3
import json
from datetime import datetime
import logging
import traceback

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS Config client
config = boto3.client('config')

def handler(event, context):
    """
    AWS Config rule to check if there is an SCP that mandates the use of guardrails
    for Amazon Bedrock model invocations.
    Control ID: FMI-02 - bedrock-guardrails-enforced
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

    # Get required parameters - guardrail ARNs that should be required
    required_guardrail_arns = []
    guardrail_arns_param = rule_parameters.get('requiredGuardrailArns', '')
    if guardrail_arns_param and guardrail_arns_param != 'none':
        required_guardrail_arns = guardrail_arns_param.split(',')
        required_guardrail_arns = [arn.strip() for arn in required_guardrail_arns if arn.strip()]
    
    # Get configurable Bedrock actions
    allowed_bedrock_actions_param = rule_parameters.get('allowedBedrockActions', 'bedrock:InvokeModel,bedrock:InvokeModelWithResponseStream')
    allowed_bedrock_actions = [action.strip() for action in allowed_bedrock_actions_param.split(',') if action.strip()]
    
    # Get configurable guardrail condition key
    guardrail_condition_key = rule_parameters.get('guardrailConditionKey', 'bedrock:guardrailIdentifier')
    
    logger.info(f"Required guardrail ARNs: {required_guardrail_arns}")
    logger.info(f"Allowed Bedrock actions: {allowed_bedrock_actions}")
    logger.info(f"Guardrail condition key: {guardrail_condition_key}")
    
    try:
        # Initialize Organizations client
        org_client = boto3.client('organizations')
        
        # Check if the account is part of an organization
        try:
            org_info = org_client.describe_organization()
            logger.info(f"Account is part of organization: {org_info['Organization']['Id']}")
        except Exception as e:
            logger.error(f"Account is not part of an AWS Organization or insufficient permissions: {str(e)}")
            compliance_type = 'NON_COMPLIANT'
            annotation = 'Account is not part of an AWS Organization, SCPs cannot be applied'
            return put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event, [])
        
        # Get all SCPs in the organization
        logger.info("Retrieving all SCPs in the organization")
        all_policies = []
        paginator = org_client.get_paginator('list_policies')
        for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
            all_policies.extend(page['Policies'])
        
        logger.info(f"Found {len(all_policies)} SCPs")
        
        # Check each SCP for Bedrock guardrail requirements
        bedrock_guardrail_scps = []
        compliant_scps = []
        
        for policy in all_policies:
            policy_id = policy['Id']
            policy_name = policy['Name']
            
            logger.info(f"Checking SCP: {policy_name} (ID: {policy_id})")
            
            # Get policy content
            policy_detail = org_client.describe_policy(PolicyId=policy_id)
            policy_content = json.loads(policy_detail['Policy']['Content'])
            
            # Check if this policy has statements requiring guardrails for Bedrock
            if 'Statement' in policy_content:
                for statement in policy_content['Statement']:
                    # Check for statements that deny Bedrock model invocation without guardrails
                    # Check if statement denies any of the configured Bedrock actions or uses wildcard
                    statement_actions = statement.get('Action', [])
                    if isinstance(statement_actions, str):
                        statement_actions = [statement_actions]
                    
                    denies_bedrock_actions = (statement.get('Effect') == 'Deny' and 
                        (any(action in statement_actions for action in allowed_bedrock_actions) or
                         'bedrock:*' in statement_actions or '*' in statement_actions))
                    
                    if denies_bedrock_actions:
                        
                        # Check if the statement has a condition requiring guardrails
                        has_guardrail_condition = False
                        required_guardrails_in_policy = []
                        
                        if 'Condition' in statement:
                            conditions = statement['Condition']
                            
                            # Check for Null condition on guardrail identifier
                            if 'Null' in conditions and guardrail_condition_key in conditions['Null']:
                                if conditions['Null'][guardrail_condition_key] == 'true':
                                    # This denies requests without a guardrail
                                    has_guardrail_condition = True
                                    bedrock_guardrail_scps.append(policy_name)
                                    
                                    # If no specific guardrails are required, this is compliant
                                    if not required_guardrail_arns:
                                        compliant_scps.append({
                                            'name': policy_name,
                                            'id': policy_id,
                                            'condition_type': 'Null',
                                            'required_guardrails': []
                                        })
                            
                            # Check for StringNotEquals condition on guardrail identifier
                            if 'StringNotEquals' in conditions and guardrail_condition_key in conditions['StringNotEquals']:
                                has_guardrail_condition = True
                                bedrock_guardrail_scps.append(policy_name)
                                
                                # Get the required guardrail ARNs from the policy
                                policy_guardrail_arns = conditions['StringNotEquals'][guardrail_condition_key]
                                if isinstance(policy_guardrail_arns, str):
                                    policy_guardrail_arns = [policy_guardrail_arns]
                                required_guardrails_in_policy = policy_guardrail_arns
                                
                                # Check if all required guardrail ARNs are in the policy
                                if required_guardrail_arns:
                                    missing_arns = [arn for arn in required_guardrail_arns if arn not in policy_guardrail_arns]
                                    
                                    if not missing_arns:
                                        compliant_scps.append({
                                            'name': policy_name,
                                            'id': policy_id,
                                            'condition_type': 'StringNotEquals',
                                            'required_guardrails': policy_guardrail_arns
                                        })
                                    else:
                                        logger.info(f"SCP {policy_name} is missing required guardrail ARNs: {missing_arns}")
                                else:
                                    # If no specific guardrails are required, any StringNotEquals condition is compliant
                                    compliant_scps.append({
                                        'name': policy_name,
                                        'id': policy_id,
                                        'condition_type': 'StringNotEquals',
                                        'required_guardrails': policy_guardrail_arns
                                    })
                            
                            # Check for ForAnyValue:StringEquals condition on guardrailIdentifier
                            # if 'ForAnyValue:StringEquals' in conditions and 'bedrock:guardrailIdentifier' in conditions['ForAnyValue:StringEquals']:
                            #     has_guardrail_condition = True
                            #     bedrock_guardrail_scps.append(policy_name)
                                
                            #     # Get the required guardrail ARNs from the policy
                            #     policy_guardrail_arns = conditions['ForAnyValue:StringEquals']['bedrock:guardrailIdentifier']
                            #     if isinstance(policy_guardrail_arns, str):
                            #         policy_guardrail_arns = [policy_guardrail_arns]
                            #     required_guardrails_in_policy = policy_guardrail_arns
                                
                            #     # Check if all required guardrail ARNs are in the policy
                            #     if required_guardrail_arns:
                            #         missing_arns = [arn for arn in required_guardrail_arns if arn not in policy_guardrail_arns]
                                    
                            #         if not missing_arns:
                            #             compliant_scps.append({
                            #                 'name': policy_name,
                            #                 'id': policy_id,
                            #                 'condition_type': 'ForAnyValue:StringEquals',
                            #                 'required_guardrails': policy_guardrail_arns
                            #             })
                            #         else:
                            #             logger.info(f"SCP {policy_name} is missing required guardrail ARNs: {missing_arns}")
                            #     else:
                            #         # If no specific guardrails are required, any ForAnyValue:StringEquals condition is compliant
                            #         compliant_scps.append({
                            #             'name': policy_name,
                            #             'id': policy_id,
                            #             'condition_type': 'ForAnyValue:StringEquals',
                            #             'required_guardrails': policy_guardrail_arns
                            #         })
        
        # Build evaluation result and individual SCP evaluations
        scp_evaluations = []
        
        # Create individual evaluations for each SCP that was checked
        for policy in all_policies:
            policy_id = policy['Id']
            policy_name = policy['Name']
            
            # Check if this SCP is relevant to Bedrock guardrails
            is_bedrock_relevant = policy_name in bedrock_guardrail_scps
            is_compliant = any(scp['id'] == policy_id for scp in compliant_scps)
            
            if is_bedrock_relevant:
                if is_compliant:
                    # Find the compliant SCP details
                    scp_detail = next(scp for scp in compliant_scps if scp['id'] == policy_id)
                    if scp_detail['condition_type'] == 'Null':
                        scp_annotation = f"SCP '{policy_name}' properly requires any guardrail for Bedrock model invocations"
                    else:
                        scp_annotation = f"SCP '{policy_name}' properly requires specific guardrails ({len(scp_detail['required_guardrails'])} configured) for Bedrock model invocations"
                    scp_compliance = 'COMPLIANT'
                else:
                    scp_annotation = f"SCP '{policy_name}' has Bedrock restrictions but does not properly enforce guardrail requirements"
                    scp_compliance = 'NON_COMPLIANT'
                
                scp_evaluations.append({
                    'policy_id': policy_id,
                    'compliance_type': scp_compliance,
                    'annotation': scp_annotation
                })
        
        # Build overall evaluation result with concise annotation
        if not bedrock_guardrail_scps:
            annotation = f"No SCPs found that mandate guardrails for Bedrock model invocations (checked {len(all_policies)} SCPs)"
            logger.info(annotation)
            compliance_type = 'NON_COMPLIANT'
        elif not compliant_scps:
            if required_guardrail_arns:
                annotation = f"Found {len(bedrock_guardrail_scps)} SCPs with Bedrock restrictions, but none include all required guardrail ARNs. See individual SCP findings for details."
            else:
                annotation = f"Found {len(bedrock_guardrail_scps)} SCPs with Bedrock restrictions, but none properly enforce guardrail requirements. See individual SCP findings for details."
            logger.info(annotation)
            compliance_type = 'NON_COMPLIANT'
        else:
            annotation = f"Found {len(compliant_scps)} compliant SCPs out of {len(bedrock_guardrail_scps)} SCPs with Bedrock restrictions. See individual SCP findings for details."
            logger.info(annotation)
            compliance_type = 'COMPLIANT'
        
    except Exception as e:
        logger.error(f"Error evaluating Bedrock guardrail SCPs: {str(e)}")
        logger.error(traceback.format_exc())
        compliance_type = 'NON_COMPLIANT'
        annotation = f'Error evaluating Bedrock guardrail SCPs: {str(e)}'
        scp_evaluations = []
    
    return put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event, scp_evaluations)

def put_evaluation_and_return(config, result_token, account_id, compliance_type, annotation, invoking_event, scp_evaluations=None):
    """
    Put evaluation results to AWS Config and return the result.
    Creates individual findings for each SCP only, without account-level summary.
    """
    # Use current time if notificationCreationTime is not available
    ordering_timestamp = invoking_event.get('notificationCreationTime')
    if not ordering_timestamp:
        ordering_timestamp = datetime.utcnow().isoformat()
    
    # Put evaluation results
    if result_token:
        logger.info("Putting evaluation results to AWS Config")
        try:
            evaluations = []
            
            # Determine overall account compliance based on SCP results
            if scp_evaluations:
                # Account compliance = worst case of all SCPs
                account_compliance = 'NON_COMPLIANT' if any(scp['compliance_type'] == 'NON_COMPLIANT' for scp in scp_evaluations) else 'COMPLIANT'
                account_annotation = f"Account has {len(scp_evaluations)} SCPs evaluated for guardrail enforcement"
                logger.info(f"Adding account-level evaluation with {len(scp_evaluations)} individual SCP evaluations")
            else:
                # Use existing logic when no SCPs found
                account_compliance = compliance_type
                account_annotation = annotation
                logger.info("Adding account-level evaluation - no SCPs found")
            
            # Always add account-level evaluation first
            evaluations.append({
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': account_id,
                'ComplianceType': account_compliance,
                'Annotation': account_annotation,
                'OrderingTimestamp': ordering_timestamp
            })
            
            # Add individual SCP evaluations if they exist
            if scp_evaluations:
                for scp_eval in scp_evaluations:
                    evaluations.append({
                        'ComplianceResourceType': 'AWS::Organizations::Policy',
                        'ComplianceResourceId': scp_eval['policy_id'],
                        'ComplianceType': scp_eval['compliance_type'],
                        'Annotation': scp_eval['annotation'],
                        'OrderingTimestamp': ordering_timestamp
                    })
            
            # Submit all evaluations in a single call
            logger.info(f"Submitting {len(evaluations)} evaluations to AWS Config")
            evaluation_result = config.put_evaluations(
                Evaluations=evaluations,
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