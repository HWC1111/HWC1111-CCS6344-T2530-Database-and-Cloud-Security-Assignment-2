import pyodbc

def get_connection():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 17 for SQL Server};"
        "SERVER=localhost;"
        "DATABASE=OnlineBookstore;"
        "UID=OnlineBookstoreApp;"
        "PWD=Pa$$w0rd;"
        "Encrypt=yes;"  
        "TrustServerCertificate=yes;" 
    )
