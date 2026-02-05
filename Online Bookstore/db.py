import pyodbc
import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

def get_connection():
    # Read the values from the .env file instead of hardcoding them
    server = os.getenv('DB_SERVER')
    database = os.getenv('DB_NAME')
    username = os.getenv('DB_USER')
    password = os.getenv('DB_PASSWORD')
    driver = os.getenv('DB_DRIVER', '{ODBC Driver 17 for SQL Server}')

    connection_string = (
        f"DRIVER={driver};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
    )

    return pyodbc.connect(connection_string)

