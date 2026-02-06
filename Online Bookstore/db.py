import pyodbc
import boto3
from botocore.exceptions import ClientError

def get_ssm_parameter(param_name, with_decryption=False):
    """
    Helper function to fetch a parameter from AWS SSM.
    """
    # Create an SSM client
    ssm = boto3.client('ssm', region_name='us-east-1')
    try:
        response = ssm.get_parameter(Name=param_name, WithDecryption=with_decryption)
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Error fetching parameter {param_name}: {e}")
        raise e

def get_connection():
    # 1. Fetch credentials securely from AWS Parameter Store
    # We don't read .env files anymore!
    try:
        server = get_ssm_parameter('/bookstore/db_server')
        user = get_ssm_parameter('/bookstore/db_user')
        password = get_ssm_parameter('/bookstore/db_password', with_decryption=True)
    except Exception as e:
        print("Failed to retrieve secrets from AWS SSM. Check IAM Role.")
        raise e
    
    # 2. Hardcoded non-secret settings
    database = 'OnlineBookstore'
    driver = '{ODBC Driver 17 for SQL Server}'

    # 3. Build Connection String
    connection_string = (
        f"DRIVER={driver};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={user};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
    )
    
    return pyodbc.connect(connection_string)
