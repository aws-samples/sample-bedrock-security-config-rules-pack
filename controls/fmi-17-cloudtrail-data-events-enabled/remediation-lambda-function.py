"""
FMI-17: CloudTrail Data Events Remediation

Simple remediation function that configures CloudTrail data events for specified resource types.
"""

import boto3
import json
import logging
import re
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
cloudtrail = boto3.client('cloudtrail')
sts = boto3.client('sts')

def validate_s3_bucket_name(bucket_name):
    """Validate S3 bucket name follows AWS naming conventions."""
    if not bucket_name:
        return False, "Bucket name is empty"
    
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        return False, "Bucket name must be between 3 and 63 characters"
    
    # S3 bucket naming rules
    bucket_pattern = re.compile(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$')
    
    if not bucket_pattern.match(bucket_name):
        return False, "Bucket name must start and end with lowercase letter or number, and contain only lowercase letters, numbers, and hyphens"
    
    # Additional checks
    if '..' in bucket_name or '--' in bucket_name:
        return False, "Bucket name cannot contain consecutive periods or hyphens"
    
    if bucket_name.startswith('xn--') or bucket_name.endswith('-s3alias'):
        return False, "Bucket name cannot start with 'xn--' or end with '-s3alias'"
    
    return True, "Valid S3 bucket name"

def validate_resource_types_format(resource_types_param):
    """Validate that resource types parameter follows the correct format."""
    if not resource_types_param:
        return False, "Resource types parameter is empty"
    
    # Pattern for AWS resource types: AWS::Service::ResourceType
    resource_type_pattern = re.compile(r'^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$')
    
    # Split by comma and validate each resource type
    resource_types = [rt.strip() for rt in resource_types_param.split(',') if rt.strip()]
    
    if not resource_types:
        return False, "No valid resource types found after parsing"
    
    for resource_type in resource_types:
        if not resource_type_pattern.match(resource_type):
            return False, f"Invalid resource type format: {resource_type}. Must be AWS::Service::ResourceType"
    
    return True, f"Validated {len(resource_types)} resource types"

def validate_trail_name(trail_name):
    """Validate CloudTrail trail name follows AWS naming conventions."""
    if not trail_name:
        return False, "Trail name is empty"
    
    if len(trail_name) < 3 or len(trail_name) > 128:
        return False, "Trail name must be between 3 and 128 characters"
    
    # CloudTrail naming rules
    trail_pattern = re.compile(r'^[a-zA-Z0-9._\-]+$')
    
    if not trail_pattern.match(trail_name):
        return False, "Trail name must contain only letters, numbers, periods, hyphens, and underscores"
    
    return True, "Valid trail name"

def handler(event, context):
    """
    Configure CloudTrail data events for specified resource types on a specific trail.
    
    Expected event parameters:
    - trailName: Name of the specific CloudTrail trail to configure
    - resourceTypes: Comma-separated list of resource types to monitor
    - includeManagementEvents: Whether to include management events (optional)
    
    Updates the specified CloudTrail trail with data event selectors. Does not create new trails or S3 buckets.
    """
    logger.info(f"Starting CloudTrail data events remediation")
    logger.info(f"Event: {json.dumps(event, default=str)}")
    
    try:
        # Get account info
        account_id = sts.get_caller_identity()['Account']
        
        # Parse input parameters
        trail_name = event.get('trailName', '')
        resource_types_param = event.get('resourceTypes', '')
        include_mgmt_events = str(event.get('includeManagementEvents', 'false')).lower() == 'true'
        
        # Validate trail name parameter
        if not trail_name:
            error_msg = "Trail name parameter is required"
            logger.error(error_msg)
            return {
                'statusCode': 400,
                'message': error_msg
            }
        
        if resource_types_param:
            is_valid_types, types_message = validate_resource_types_format(resource_types_param)
            if not is_valid_types:
                error_msg = f"Invalid resource types: {types_message}"
                logger.error(error_msg)
                return {
                    'statusCode': 400,
                    'message': error_msg
                }
            logger.info(types_message)
        
        # Parse resource types
        if resource_types_param:
            resource_types = [rt.strip() for rt in resource_types_param.split(',') if rt.strip()]
        else:
            # Default to Bedrock resource types
            resource_types = [
                'AWS::Bedrock::Model',
                'AWS::Bedrock::AsyncInvoke', 
                'AWS::Bedrock::Guardrail',
                'AWS::Bedrock::AgentAlias',
                'AWS::Bedrock::FlowAlias',
                'AWS::Bedrock::InlineAgent',
                'AWS::Bedrock::KnowledgeBase',
                'AWS::Bedrock::PromptVersion',
                'AWS::Bedrock::Session',
                'AWS::Bedrock::FlowExecution'
            ]
        
        # Validate that we have resource types to configure
        if not resource_types:
            error_msg = "No valid resource types found after parsing parameters"
            logger.error(error_msg)
            return {
                'statusCode': 400,
                'message': error_msg
            }
        
        logger.info(f"Configuring data events for {len(resource_types)} resource types on trail: {trail_name}")
        
        # Find and validate the specified trail
        target_trail = find_specific_trail(trail_name)
        
        if not target_trail:
            error_msg = f"CloudTrail trail '{trail_name}' not found or not actively logging. Please ensure the trail exists and is active."
            logger.error(error_msg)
            return {
                'statusCode': 400,
                'message': error_msg
            }
        
        # Configure data events on the specified trail
        trail_arn = target_trail['TrailARN']
        logger.info(f"Updating trail: {trail_name} (ARN: {trail_arn})")
        
        try:
            update_trail_event_selectors(trail_arn, resource_types, include_mgmt_events)
            
            message = f"Successfully configured data events for {len(resource_types)} resource types on trail: {trail_name}"
            logger.info(message)
            
            return {
                'statusCode': 200,
                'message': message,
                'trailName': trail_name,
                'trailArn': trail_arn,
                'resourceTypesCount': len(resource_types)
            }
            
        except Exception as e:
            error_msg = f"Failed to update trail '{trail_name}' with data events: {str(e)}"
            logger.error(error_msg)
            return {
                'statusCode': 500,
                'message': error_msg
            }
        
    except Exception as e:
        error_msg = f"Failed to configure CloudTrail data events: {str(e)}"
        logger.error(error_msg)
        return {
            'statusCode': 500,
            'message': error_msg
        }

def find_specific_trail(trail_name):
    """Find and validate a specific CloudTrail trail by name."""
    try:
        logger.info(f"Looking for trail: {trail_name}")
        
        # Try to get the specific trail first
        try:
            response = cloudtrail.describe_trails(trailNameList=[trail_name])
            trails = response.get('trailList', [])
            
            if not trails:
                logger.warning(f"Trail '{trail_name}' not found using direct lookup")
                return None
                
            trail = trails[0]
            
        except Exception as e:
            logger.warning(f"Direct trail lookup failed: {e}. Trying to search all trails.")
            
            # Fallback: search through all trails
            response = cloudtrail.describe_trails()
            all_trails = response.get('trailList', [])
            
            trail = None
            for t in all_trails:
                if t['Name'] == trail_name:
                    trail = t
                    break
            
            if not trail:
                logger.error(f"Trail '{trail_name}' not found in account")
                return None
        
        # Check if trail is actively logging
        trail_arn = trail['TrailARN']
        try:
            status_response = cloudtrail.get_trail_status(Name=trail_arn)
            is_logging = status_response.get('IsLogging', False)
            
            if not is_logging:
                logger.error(f"Trail '{trail_name}' exists but is not actively logging")
                return None
                
            logger.info(f"Found active trail: {trail_name} (ARN: {trail_arn})")
            return trail
            
        except Exception as e:
            logger.error(f"Could not check status for trail '{trail_name}': {e}")
            return None
        
    except Exception as e:
        logger.error(f"Error finding trail '{trail_name}': {e}")
        raise

# Note: S3 bucket creation functions removed as per updated design.
# This remediation function only modifies existing CloudTrail trails.
# S3 buckets and trails must be created separately before running remediation.

def update_trail_event_selectors(trail_arn, resource_types, include_mgmt_events):
    """Update CloudTrail event selectors to include data events for specified resource types."""
    try:
        # Validate that we have resource types to configure
        if not resource_types:
            logger.error("No resource types provided for event selector configuration")
            raise ValueError("Cannot configure event selectors: No resource types specified")
        
        logger.info(f"Configuring event selectors for {len(resource_types)} resource types")
        
        # Get current selectors
        response = cloudtrail.get_event_selectors(TrailName=trail_arn)
        current_selectors = response.get('AdvancedEventSelectors', [])
        
        # Remove existing data event selectors for the same resource types
        filtered_selectors = []
        for selector in current_selectors:
            if not is_duplicate_data_event_selector(selector, resource_types):
                filtered_selectors.append(selector)
        
        # Add data event selectors for each resource type
        for resource_type in resource_types:
            selector = {
                'Name': f'DataEvents-{resource_type.replace("::", "-")}',
                'FieldSelectors': [
                    {
                        'Field': 'eventCategory',
                        'Equals': ['Data']
                    },
                    {
                        'Field': 'resources.type',
                        'Equals': [resource_type]
                    }
                ]
            }
            filtered_selectors.append(selector)
            logger.info(f"Added data event selector for: {resource_type}")
        
        # Add management events if requested
        if include_mgmt_events and not has_management_event_selector(current_selectors):
            mgmt_selector = create_management_event_selector()
            filtered_selectors.append(mgmt_selector)
            logger.info("Added management events selector")
        
        # Update trail with new selectors
        cloudtrail.put_event_selectors(
            TrailName=trail_arn,
            AdvancedEventSelectors=filtered_selectors
        )
        
        logger.info(f"Successfully configured {len(filtered_selectors)} event selectors")
        
    except Exception as e:
        logger.error(f"Error configuring data events: {e}")
        raise

def is_duplicate_data_event_selector(selector, resource_types):
    """Check if selector is a duplicate data event selector for any of the specified resource types."""
    field_selectors = selector.get('FieldSelectors', [])
    
    has_data_category = False
    has_target_resource = False
    
    for field in field_selectors:
        field_name = field.get('Field', '')
        field_values = field.get('Equals', [])
        
        if field_name == 'eventCategory' and 'Data' in field_values:
            has_data_category = True
        
        if field_name == 'resources.type':
            for value in field_values:
                if value in resource_types:
                    has_target_resource = True
                    break
    
    return has_data_category and has_target_resource

def has_management_event_selector(selectors):
    """Check if selectors already include management events."""
    for selector in selectors:
        field_selectors = selector.get('FieldSelectors', [])
        for field in field_selectors:
            if (field.get('Field') == 'eventCategory' and 
                'Management' in field.get('Equals', [])):
                return True
    return False

def create_management_event_selector():
    """Create a management event selector configuration."""
    return {
        'Name': 'ManagementEvents',
        'FieldSelectors': [
            {
                'Field': 'eventCategory',
                'Equals': ['Management']
            }
        ]
    }