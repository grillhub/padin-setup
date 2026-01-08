import json
import boto3
import urllib3
import os
from botocore.exceptions import ClientError

def send_response(event, context, response_status, response_data=None, physical_resource_id=None):
    """Send response to CloudFormation"""
    if response_data is None:
        response_data = {}
    
    response_url = event['ResponseURL']
    response_body = {
        'Status': response_status,
        'Reason': f'See CloudWatch Log Stream: {context.log_stream_name}',
        'PhysicalResourceId': physical_resource_id or context.log_stream_name,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data
    }
    
    json_response_body = json.dumps(response_body)
    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }
    
    try:
        http = urllib3.PoolManager()
        response = http.request('PUT', response_url, body=json_response_body, headers=headers)
        print(f"Response sent to CloudFormation: {response.status}")
    except Exception as e:
        print(f"Failed to send response to CloudFormation: {str(e)}")

def register_admin_user():
    """Register the admin user in Cognito"""
    cognito = boto3.client('cognito-idp')
    user_pool_id = os.environ.get('USER_POOL_ID')
    admin_email = os.environ.get('ADMIN_EMAIL')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    
    if not user_pool_id or not admin_email or not admin_password:
        raise Exception('Missing required environment variables')
    
    try:
        print(f"Creating admin user: {admin_email}")
        
        # Create the admin user
        response = cognito.admin_create_user(
            UserPoolId=user_pool_id,
            Username=admin_email,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': admin_email
                },
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ],
            TemporaryPassword=admin_password,
            MessageAction='SUPPRESS'  # Don't send welcome email
        )
        
        print(f"Admin user created successfully: {response['User']['Username']}")
        
        # Set permanent password
        cognito.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=admin_email,
            Password=admin_password,
            Permanent=True
        )
        
        print("Admin password set as permanent")
        
        # Confirm the user (in case needed)
        try:
            cognito.admin_confirm_sign_up(
                UserPoolId=user_pool_id,
                Username=admin_email
            )
            print("Admin user confirmed")
        except ClientError as e:
            # User might already be confirmed
            if e.response['Error']['Code'] != 'NotAuthorizedException':
                print(f"Warning during confirmation: {str(e)}")
        
        return {
            'message': f'Admin user {admin_email} registered successfully',
            'username': admin_email,
            'user_status': response['User']['UserStatus']
        }
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UsernameExistsException':
            print(f"Admin user {admin_email} already exists, updating password...")
            
            # Update existing user's password
            cognito.admin_set_user_password(
                UserPoolId=user_pool_id,
                Username=admin_email,
                Password=admin_password,
                Permanent=True
            )
            
            return {
                'message': f'Admin user {admin_email} already exists, password updated',
                'username': admin_email,
                'user_status': 'CONFIRMED'
            }
        else:
            raise e

def lambda_handler(event, context):
    """Handle CloudFormation Custom Resource events"""
    print(f"Received event: {json.dumps(event)}")
    
    try:
        request_type = event['RequestType']
        
        if request_type == 'Create' or request_type == 'Update':
            # Register/update the admin user
            result = register_admin_user()
            send_response(event, context, 'SUCCESS', result)
        
        elif request_type == 'Delete':
            # For delete, we just acknowledge - don't delete the user
            print("Delete request received - admin user will remain in Cognito")
            send_response(event, context, 'SUCCESS', {'message': 'Delete completed - admin user preserved'})
        
        else:
            print(f"Unknown request type: {request_type}")
            send_response(event, context, 'FAILED', {'error': f'Unknown request type: {request_type}'})
    
    except Exception as e:
        print(f"Error: {str(e)}")
        send_response(event, context, 'FAILED', {'error': str(e)})