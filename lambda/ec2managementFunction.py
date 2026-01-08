import json
import boto3
import os
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import uuid
import base64
import hmac
import hashlib

# EC2 instance tag (tag value to search for)
EC2_INSTANCE_TAG = os.environ.get('EC2_INSTANCE_TAG', '')

# S3 configuration for activity logging
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', '')  # Configure this bucket name as needed
S3_LOG_PREFIX = "ec2-management-logs/"

# Cognito configuration
USER_POOL_ID = os.environ.get('USER_POOL_ID', '')
CLIENT_ID = os.environ.get('CLIENT_ID', '')
REGION = os.environ.get('COGNITO_REGION', 'us-east-1')

# Initialize Cognito client
cognito = boto3.client('cognito-idp', region_name=REGION)

def get_instances_by_tag(ec2_client, tag_value):
    """
    Find EC2 instances by tag value.
    Searches for instances with any tag matching the specified value.
    
    Args:
        ec2_client: boto3 EC2 client
        tag_value (str): Tag value to search for
        
    Returns:
        list: List of instance IDs matching the tag
    """
    if not tag_value:
        return []
    
    try:
        # Search for instances with the specified tag value
        # This searches across all tag keys for the matching value
        filters = [
            {
                'Name': 'tag-value',
                'Values': [tag_value]
            },
            {
                'Name': 'instance-state-name',
                'Values': ['pending', 'running', 'stopping', 'stopped']
            }
        ]
        
        response = ec2_client.describe_instances(Filters=filters)
        
        instance_ids = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_ids.append(instance['InstanceId'])
        
        return instance_ids
    except ClientError as e:
        print(f"Error finding instances by tag: {str(e)}")
        return []

def verify_access_token(access_token):
    """Verify access token using Cognito's GetUser API"""
    try:
        # Remove 'Bearer ' prefix if present
        if access_token.startswith('Bearer '):
            access_token = access_token[7:]
        
        # Use Cognito's GetUser API to verify the token
        response = cognito.get_user(AccessToken=access_token)
        
        # Extract user information
        user_info = {
            'username': response.get('Username'),
            'user_attributes': {}
        }
        
        # Parse user attributes
        for attr in response.get('UserAttributes', []):
            user_info['user_attributes'][attr['Name']] = attr['Value']
        
        return user_info
        
    except ClientError as e:
        print(f"Token verification error: {str(e)}")
        return None
    except Exception as e:
        print(f"Unexpected token verification error: {str(e)}")
        return None

def handle_login(body):
    """Handle user login with Cognito"""
    email = body.get('email')
    password = body.get('password')
    
    if not email or not password:
        return {
            'statusCode': 400,
            'body': json.dumps({
                'success': False,
                'message': 'Email and password are required'
            })
        }
    
    try:
        result = cognito.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            ClientId=CLIENT_ID,
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            }
        )
        
        auth_result = result.get('AuthenticationResult', {})
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'message': 'Login successful',
                'authResult': {
                    'accessToken': auth_result.get('AccessToken'),
                    'idToken': auth_result.get('IdToken'),
                    'refreshToken': auth_result.get('RefreshToken'),
                    'expiresIn': auth_result.get('ExpiresIn')
                }
            })
        }
    except ClientError as error:
        print(f'Login error: {str(error)}')
        return {
            'statusCode': 401,
            'body': json.dumps({
                'success': False,
                'message': str(error)
            })
        }

def require_authentication(func):
    """Decorator to require authentication for protected functions"""
    def wrapper(*args, **kwargs):
        # Get the request data from the first argument (should be the event or body)
        request_data = args[0] if args else {}
        
        # Extract token from request
        token = None
        if isinstance(request_data, dict):
            token = request_data.get('token') or request_data.get('accessToken')
            
            # Also check in headers if available
            headers = request_data.get('headers', {})
            if not token and headers:
                auth_header = headers.get('Authorization') or headers.get('authorization')
                if auth_header:
                    token = auth_header
        
        if not token:
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Authentication token required'
                })
            }
        
        # Verify the token
        user_info = verify_access_token(token)
        if not user_info:
            return {
                'statusCode': 401,
                'body': json.dumps({
                    'error': 'Invalid or expired token'
                })
            }
        
        # Add user info to the request data
        if isinstance(request_data, dict):
            request_data['user_info'] = user_info
        
        # Call the original function
        return func(*args, **kwargs)
    
    return wrapper


def log_activity_to_s3(action, instances_data, request_details=None, error_info=None):
    """
    Log EC2 activity to S3 bucket with comprehensive information
    
    Args:
        action (str): The action performed ('start' or 'stop')
        instances_data (list): List of instances affected with their state changes
        request_details (dict): Details about the request (e.g., is_sam2_enable)
        error_info (dict): Error information if the action failed
    """
    s3_client = boto3.client('s3')
    
    try:
        # Generate unique log ID and timestamp
        log_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        epoch_timestamp = int(timestamp.timestamp())
        date_str = timestamp.strftime('%Y/%m/%d')
        
        # Prepare log entry
        log_entry = {
            'log_id': log_id,
            'timestamp': epoch_timestamp,
            'action': action,
            'status': 'success' if not error_info else 'failed',
            'request_details': request_details or {},
            'instances': instances_data,
            'error_info': error_info,
            'metadata': {
                'lambda_function': 'lambda_functionV4',
                'aws_region': boto3.Session().region_name or 'us-east-1',
                'execution_timestamp': epoch_timestamp
            }
        }
        
        # Create S3 key with date partitioning for better organization
        s3_key = f"{S3_LOG_PREFIX}{date_str}/{action}-{timestamp.strftime('%Y%m%d-%H%M%S')}-{log_id[:8]}.json"
        
        # Upload log to S3
        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=json.dumps(log_entry, indent=2),
            ContentType='application/json',
            Metadata={
                'log-id': log_id,
                'action': action,
                'status': log_entry['status'],
                'timestamp': str(epoch_timestamp)
            }
        )
        
        print(f"Activity logged to S3: s3://{S3_BUCKET_NAME}/{s3_key}")
        return {'success': True, 'log_id': log_id, 's3_key': s3_key}
        
    except Exception as e:
        # Log error but don't fail the main operation
        error_msg = f"Failed to log activity to S3: {str(e)}"
        print(error_msg)
        return {'success': False, 'error': error_msg}


def authenticate_request(body):
    """Check if request contains valid authentication token"""
    if not body or not isinstance(body, dict):
        return False, "Invalid request format"
    
    token = body.get('token') or body.get('accessToken')
    if not token:
        return False, "Authentication token required"
    
    user_info = verify_access_token(token)
    if not user_info:
        return False, "Invalid or expired token"
    
    return True, user_info

def get_activity_logs(body):
    """
    Retrieve activity logs from S3 bucket with filtering and pagination options
    
    Args:
        body (dict): Request parameters including:
            - token (str): Authentication token
            - date_from (str): Start date for filtering (YYYY-MM-DD format)
            - date_to (str): End date for filtering (YYYY-MM-DD format)
            - action (str): Filter by action type ('start', 'stop', or 'all')
            - status (str): Filter by status ('success', 'failed', or 'all')
            - limit (int): Maximum number of logs to return (default: 50, max: 1000)
            - log_id (str): Specific log ID to retrieve
    """
    # Authenticate the request
    is_authenticated, auth_result = authenticate_request(body)
    if not is_authenticated:
        return {
            'statusCode': 401,
            'body': json.dumps({'error': auth_result})
        }
    
    s3_client = boto3.client('s3')
    
    # Handle missing body parameter
    if not body:
        body = {}
    
    # Parse JSON if body is a string
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid JSON in body parameter'
                })
            }
    
    # Extract parameters with defaults
    date_from = body.get('date_from')
    date_to = body.get('date_to')
    action_filter = body.get('action', 'all').lower()
    status_filter = body.get('status', 'all').lower()
    limit = min(body.get('limit', 50), 1000)  # Cap at 1000 logs
    specific_log_id = body.get('log_id')
    
    try:
        logs = []
        
        # If specific log ID is provided, try to find it directly
        if specific_log_id:
            try:
                # Search through date-partitioned structure for the specific log
                paginator = s3_client.get_paginator('list_objects_v2')
                page_iterator = paginator.paginate(
                    Bucket=S3_BUCKET_NAME,
                    Prefix=S3_LOG_PREFIX
                )
                
                found_log = None
                for page in page_iterator:
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            if specific_log_id[:8] in obj['Key']:
                                # Try to retrieve and parse the log
                                try:
                                    response = s3_client.get_object(
                                        Bucket=S3_BUCKET_NAME,
                                        Key=obj['Key']
                                    )
                                    log_content = json.loads(response['Body'].read().decode('utf-8'))
                                    if log_content.get('log_id') == specific_log_id:
                                        found_log = log_content
                                        break
                                except Exception:
                                    continue
                            
                        if found_log:
                            break
                
                if found_log:
                    return {
                        'statusCode': 200,
                        'body': json.dumps({
                            'action': 'getActivityLogs',
                            'total_logs': 1,
                            'filters': {
                                'log_id': specific_log_id
                            },
                            'logs': [found_log]
                        })
                    }
                else:
                    return {
                        'statusCode': 404,
                        'body': json.dumps({
                            'error': f'Log with ID {specific_log_id} not found'
                        })
                    }
                    
            except Exception as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({
                        'error': f'Failed to retrieve specific log: {str(e)}'
                    })
                }
        
        # General log retrieval with filtering
        current_date = datetime.utcnow()
        
        # Set default date range (last 30 days if not specified)
        if not date_from:
            date_from = (current_date - timedelta(days=30)).strftime('%Y-%m-%d')
        if not date_to:
            date_to = current_date.strftime('%Y-%m-%d')
        
        # Validate date format
        try:
            start_date = datetime.strptime(date_from, '%Y-%m-%d')
            end_date = datetime.strptime(date_to, '%Y-%m-%d')
        except ValueError:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid date format. Use YYYY-MM-DD format.'
                })
            }
        
        # Validate date range
        if start_date > end_date:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'date_from cannot be later than date_to'
                })
            }
        
        # List objects in the date range
        date_prefixes = []
        current = start_date
        while current <= end_date:
            date_prefix = f"{S3_LOG_PREFIX}{current.strftime('%Y/%m/%d')}/"
            date_prefixes.append(date_prefix)
            current += timedelta(days=1)
        
        # Collect logs from each date prefix
        for prefix in date_prefixes:
            try:
                paginator = s3_client.get_paginator('list_objects_v2')
                page_iterator = paginator.paginate(
                    Bucket=S3_BUCKET_NAME,
                    Prefix=prefix
                )
                
                for page in page_iterator:
                    if 'Contents' in page:
                        # Sort by last modified date (newest first)
                        objects = sorted(page['Contents'], key=lambda x: x['LastModified'], reverse=True)
                        
                        for obj in objects:
                            if len(logs) >= limit:
                                break
                                
                            try:
                                # Apply action filter to filename if specified
                                if action_filter != 'all':
                                    if not obj['Key'].split('/')[-1].startswith(f"{action_filter}-"):
                                        continue
                                
                                # Retrieve and parse log content
                                response = s3_client.get_object(
                                    Bucket=S3_BUCKET_NAME,
                                    Key=obj['Key']
                                )
                                log_content = json.loads(response['Body'].read().decode('utf-8'))
                                
                                # Apply status filter
                                if status_filter != 'all' and log_content.get('status') != status_filter:
                                    continue
                                
                                # Add S3 metadata
                                log_content['s3_metadata'] = {
                                    'key': obj['Key'],
                                    'last_modified': obj['LastModified'].isoformat(),
                                    'size': obj['Size']
                                }
                                
                                logs.append(log_content)
                                
                            except Exception as e:
                                # Skip corrupted or inaccessible logs
                                print(f"Warning: Could not process log {obj['Key']}: {str(e)}")
                                continue
                    
                    if len(logs) >= limit:
                        break
            except Exception as e:
                print(f"Warning: Could not list objects for prefix {prefix}: {str(e)}")
                continue
        
        # Sort logs by timestamp (newest first)
        logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'action': 'getActivityLogs',
                'total_logs': len(logs),
                'filters': {
                    'date_from': date_from,
                    'date_to': date_to,
                    'action': action_filter,
                    'status': status_filter,
                    'limit': limit
                },
                'logs': logs
            })
        }
        
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Failed to retrieve activity logs: {str(e)}'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Unexpected error retrieving logs: {str(e)}'
            })
        }


def get_ec2_status(body=None):
    """Get the status of the EC2 instance with detailed state and status checks"""
    # Authenticate the request
    is_authenticated, auth_result = authenticate_request(body)
    if not is_authenticated:
        return {
            'statusCode': 401,
            'body': json.dumps({'error': auth_result})
        }
    
    ec2_client = boto3.client('ec2')
    
    try:
        # Find instances by tag
        instance_ids = get_instances_by_tag(ec2_client, EC2_INSTANCE_TAG)
        
        if not instance_ids:
            return {
                'statusCode': 404,
                'body': json.dumps({
                    'error': f'No EC2 instances found with tag: {EC2_INSTANCE_TAG}'
                })
            }
        
        # Get basic instance information
        response = ec2_client.describe_instances(
            InstanceIds=instance_ids
        )
        
        # Get instance status checks (only for running instances)
        running_instances = []
        instances_status = {}
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                state = instance['State']['Name']
                state_code = instance['State']['Code']
                
                # Get storage information
                storage_info = []
                if 'BlockDeviceMappings' in instance:
                    for block_device in instance['BlockDeviceMappings']:
                        if 'Ebs' in block_device:
                            ebs = block_device['Ebs']
                            # Get volume details to fetch volume size
                            try:
                                volume_response = ec2_client.describe_volumes(
                                    VolumeIds=[ebs['VolumeId']]
                                )
                                volume_size = volume_response['Volumes'][0]['Size'] if volume_response['Volumes'] else 'N/A'
                                volume_type = volume_response['Volumes'][0]['VolumeType'] if volume_response['Volumes'] else 'N/A'
                            except:
                                volume_size = 'N/A'
                                volume_type = 'EBS'
                            
                            storage_info.append({
                                'device_name': block_device['DeviceName'],
                                'volume_id': ebs['VolumeId'],
                                'volume_size_gb': volume_size,
                                'volume_type': volume_type,
                                'delete_on_termination': ebs.get('DeleteOnTermination', False)
                            })
                
                # Get additional volume information if available
                root_device_name = instance.get('RootDeviceName', 'N/A')

                # Basic instance information
                instance_info = {
                    'instance_id': instance_id,
                    'instance_state': {
                        'name': state,
                        'code': state_code
                    },
                    'public_ipv4_address': instance.get('PublicIpAddress', 'N/A'),
                    'instance_type': instance.get('InstanceType', 'N/A'),
                    'storage': {
                        'root_device_name': root_device_name,
                        'root_device_type': instance.get('RootDeviceType', 'N/A'),
                        'block_devices': storage_info
                    },
                    'status_checks': {
                        'system_status': 'N/A',
                        'instance_status': 'N/A',
                        'system_status_details': 'N/A',
                        'instance_status_details': 'N/A'
                    }
                }
                
                # Keep track of running instances for status checks
                if state == 'running':
                    running_instances.append(instance_id)
                
                # Add instance to status (using first matching instance or all if multiple)
                if instance_id in instance_ids:
                    # Use instance_id as key, or 'ec2lite' for single instance
                    if len(instance_ids) == 1:
                        instances_status['ec2lite'] = instance_info
                    else:
                        instances_status[instance_id] = instance_info
        
        # Get status checks for running instances
        if running_instances:
            try:
                status_response = ec2_client.describe_instance_status(
                    InstanceIds=running_instances,
                    IncludeAllInstances=True
                )
                
                # Update status check information
                for status in status_response['InstanceStatuses']:
                    instance_id = status['InstanceId']
                    
                    # Find the corresponding instance in our status dict
                    target_instance = None
                    if instances_status.get('ec2lite', {}).get('instance_id') == instance_id:
                        target_instance = instances_status['ec2lite']
                    elif instance_id in instances_status:
                        target_instance = instances_status[instance_id]
                    
                    if target_instance:
                        # Update status check information
                        system_status = status.get('SystemStatus', {})
                        instance_status = status.get('InstanceStatus', {})
                        
                        target_instance['status_checks'] = {
                            'system_status': system_status.get('Status', 'N/A'),
                            'instance_status': instance_status.get('Status', 'N/A'),
                            'system_status_details': system_status.get('Details', []),
                            'instance_status_details': instance_status.get('Details', [])
                        }
                        
            except ClientError as status_error:
                # If status check fails, keep N/A values but don't fail the whole request
                print(f"Warning: Could not get status checks: {str(status_error)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'action': 'getEC2Status',
                'instances': instances_status
            })
        }
        
    except ClientError as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Failed to get EC2 status: {str(e)}'
            })
        }

def start_ec2_instances(body):
    """Start EC2 instance"""
    # Authenticate the request
    is_authenticated, auth_result = authenticate_request(body)
    if not is_authenticated:
        return {
            'statusCode': 401,
            'body': json.dumps({'error': auth_result})
        }
    
    ec2_client = boto3.client('ec2')
    
    # Handle missing body parameter
    if not body:
        body = {}
    
    # Parse JSON if body is a string
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid JSON in body parameter'
                })
            }
    
    is_sam2_enable = body.get('is_sam2_enable', True)  # Default to True for backward compatibility
    
    # Find instances by tag
    instance_ids = get_instances_by_tag(ec2_client, EC2_INSTANCE_TAG)
    
    if not instance_ids:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'error': f'No EC2 instances found with tag: {EC2_INSTANCE_TAG}'
            })
        }
    
    message = f'EC2 instance(s) start initiated (tag: {EC2_INSTANCE_TAG})'

    try:
        response = ec2_client.start_instances(
            InstanceIds=instance_ids
        )
        
        starting_instances = []
        for instance in response['StartingInstances']:
            starting_instances.append({
                'instance_id': instance['InstanceId'],
                'current_state': instance['CurrentState']['Name'],
                'previous_state': instance['PreviousState']['Name']
            })
        
        # Log successful start activity to S3
        log_result = log_activity_to_s3(
            action='start',
            instances_data=starting_instances,
            request_details={
                'is_sam2_enable': is_sam2_enable,
                'requested_instances': len(instance_ids),
                'instance_ids': instance_ids,
                'message': message
            }
        )
        
        # Prepare response
        response_body = {
            'action': 'start',
            'message': message,
            'is_sam2_enable': is_sam2_enable,
            'instances': starting_instances
        }
        
        # Add log information to response if logging was successful
        if log_result['success']:
            response_body['activity_log'] = {
                'logged': True,
                'log_id': log_result['log_id'],
                's3_location': f"s3://{S3_BUCKET_NAME}/{log_result['s3_key']}"
            }
        else:
            response_body['activity_log'] = {
                'logged': False,
                'error': log_result['error']
            }
        
        return {
            'statusCode': 200,
            'body': json.dumps(response_body)
        }
        
    except ClientError as e:
        error_message = f'Failed to start EC2 instances: {str(e)}'
        
        # Log failed start activity to S3
        log_result = log_activity_to_s3(
            action='start',
            instances_data=[],
            request_details={
                'is_sam2_enable': is_sam2_enable,
                'requested_instances': len(instance_ids),
                'instance_ids': instance_ids,
                'message': message
            },
            error_info={
                'error_type': 'ClientError',
                'error_message': error_message,
                'error_code': e.response.get('Error', {}).get('Code', 'Unknown') if hasattr(e, 'response') else 'Unknown'
            }
        )
        
        # Prepare error response
        error_response = {
            'error': error_message
        }
        
        # Add log information to response if logging was successful
        if log_result['success']:
            error_response['activity_log'] = {
                'logged': True,
                'log_id': log_result['log_id'],
                's3_location': f"s3://{S3_BUCKET_NAME}/{log_result['s3_key']}"
            }
        
        return {
            'statusCode': 500,
            'body': json.dumps(error_response)
        }

def stop_ec2_instances(body):
    """Stop EC2 instance"""
    # Authenticate the request
    is_authenticated, auth_result = authenticate_request(body)
    if not is_authenticated:
        return {
            'statusCode': 401,
            'body': json.dumps({'error': auth_result})
        }
    
    ec2_client = boto3.client('ec2')
    
    # Handle missing body parameter
    if not body:
        body = {}
    
    # Parse JSON if body is a string
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Invalid JSON in body parameter'
                })
            }
    
    is_sam2_enable = body.get('is_sam2_enable', True)  # Default to True for backward compatibility
    
    # Find instances by tag
    instance_ids = get_instances_by_tag(ec2_client, EC2_INSTANCE_TAG)
    
    if not instance_ids:
        return {
            'statusCode': 404,
            'body': json.dumps({
                'error': f'No EC2 instances found with tag: {EC2_INSTANCE_TAG}'
            })
        }
    
    message = f'EC2 instance(s) stop initiated (tag: {EC2_INSTANCE_TAG})'

    try:
        response = ec2_client.stop_instances(
            InstanceIds=instance_ids
        )
        
        stopping_instances = []
        for instance in response['StoppingInstances']:
            stopping_instances.append({
                'instance_id': instance['InstanceId'],
                'current_state': instance['CurrentState']['Name'],
                'previous_state': instance['PreviousState']['Name']
            })
        
        # Log successful stop activity to S3
        log_result = log_activity_to_s3(
            action='stop',
            instances_data=stopping_instances,
            request_details={
                'is_sam2_enable': is_sam2_enable,
                'requested_instances': len(instance_ids),
                'instance_ids': instance_ids,
                'message': message
            }
        )
        
        # Prepare response
        response_body = {
            'action': 'stop',
            'message': message,
            'is_sam2_enable': is_sam2_enable,
            'instances': stopping_instances
        }
        
        # Add log information to response if logging was successful
        if log_result['success']:
            response_body['activity_log'] = {
                'logged': True,
                'log_id': log_result['log_id'],
                's3_location': f"s3://{S3_BUCKET_NAME}/{log_result['s3_key']}"
            }
        else:
            response_body['activity_log'] = {
                'logged': False,
                'error': log_result['error']
            }
        
        return {
            'statusCode': 200,
            'body': json.dumps(response_body)
        }
        
    except ClientError as e:
        error_message = f'Failed to stop EC2 instances: {str(e)}'
        
        # Log failed stop activity to S3
        log_result = log_activity_to_s3(
            action='stop',
            instances_data=[],
            request_details={
                'is_sam2_enable': is_sam2_enable,
                'requested_instances': len(instance_ids),
                'instance_ids': instance_ids,
                'message': message
            },
            error_info={
                'error_type': 'ClientError',
                'error_message': error_message,
                'error_code': e.response.get('Error', {}).get('Code', 'Unknown') if hasattr(e, 'response') else 'Unknown'
            }
        )
        
        # Prepare error response
        error_response = {
            'error': error_message
        }
        
        # Add log information to response if logging was successful
        if log_result['success']:
            error_response['activity_log'] = {
                'logged': True,
                'log_id': log_result['log_id'],
                's3_location': f"s3://{S3_BUCKET_NAME}/{log_result['s3_key']}"
            }
        
        return {
            'statusCode': 500,
            'body': json.dumps(error_response)
        }

def lambda_handler(event, context):
    """Main Lambda handler that routes to appropriate action functions"""
    try:
        # Handle different event structures (direct invocation vs HTTP API Gateway)
        if 'body' in event and isinstance(event['body'], str):
            # HTTP API Gateway event - parse JSON from body
            try:
                request_data = json.loads(event['body'])
            except json.JSONDecodeError:
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'Invalid JSON in request body'
                    })
                }
        elif 'action' in event:
            # Direct Lambda invocation - use event directly
            request_data = event
        else:
            # Try to use event as-is (for backward compatibility)
            request_data = event
        
        # Extract action and body from parsed request data
        action = request_data.get('action')
        body = request_data.get('body')
        
        if not action:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'Missing action parameter. Valid actions: login, getEC2Status, start, stop, getActivityLogs'
                })
            }
        
        # Route to appropriate function based on action
        if action == "login":
            return handle_login(body)
        elif action == "getEC2Status":
            return get_ec2_status(body)
        elif action == "start":
            return start_ec2_instances(body)
        elif action == "stop":
            return stop_ec2_instances(body)
        elif action == "getActivityLogs":
            return get_activity_logs(body)
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': f'Invalid action: {action}. Valid actions: login, getEC2Status, start, stop, getActivityLogs'
                })
            }
    
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f'Unexpected error: {str(e)}'
            })
        }