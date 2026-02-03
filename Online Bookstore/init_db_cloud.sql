/* CLOUD MIGRATION NOTES:
   1. TDE is removed (Replaced by AWS RDS Storage Encryption).
   2. File Auditing is removed (Replaced by AWS CloudTrail/CloudWatch).
   3. Master Key backups are managed by AWS.
*/

USE master;
GO

-- 1. CLEANUP
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'OnlineBookstore')
BEGIN
    ALTER DATABASE OnlineBookstore SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE OnlineBookstore;
END
GO

-- 2. DATABASE CREATION
CREATE DATABASE OnlineBookstore;
GO

USE OnlineBookstore;
GO

-- 3. SCHEMA & TABLES
CREATE SCHEMA Application;
GO
CREATE SCHEMA Sales;
GO
CREATE SCHEMA Security;
GO

-- Users Table
CREATE TABLE Application.Users (
    UserID INT IDENTITY PRIMARY KEY,
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    Role NVARCHAR(20) NOT NULL
);
GO

-- Login Tracking (Brute Force Prevention)
CREATE TABLE Application.LoginTracking (
    Username NVARCHAR(50) PRIMARY KEY,
    FailedAttempts INT DEFAULT 0,
    LockoutEnd DATETIME NULL
);
GO

-- Members Table
CREATE TABLE Application.Members (
    MemberID INT IDENTITY PRIMARY KEY,
    UserID INT UNIQUE NOT NULL,
    FullName NVARCHAR(100),
    ICNumber NVARCHAR(20),
    Email NVARCHAR(100) MASKED WITH (FUNCTION = 'email()'),
    CreatedAt DATETIME DEFAULT GETDATE(),
    FOREIGN KEY (UserID) REFERENCES Application.Users(UserID)
);
GO

-- Books Table
CREATE TABLE Sales.Books (
    BookID INT IDENTITY PRIMARY KEY,
    Title NVARCHAR(200),
    Author NVARCHAR(100),
    Price DECIMAL(10,2),
    Stock INT
);
GO

-- Orders Table
CREATE TABLE Sales.Orders (
    OrderID INT IDENTITY PRIMARY KEY,
    UserID INT,
    OrderDate DATETIME DEFAULT GETDATE(),
    TotalAmount DECIMAL(10,2),
    DiscountAmount DECIMAL(10,2),
    FOREIGN KEY (UserID) REFERENCES Application.Users(UserID)
);
GO

-- OrderItems Table
CREATE TABLE Sales.OrderItems (
    OrderItemID INT IDENTITY PRIMARY KEY,
    OrderID INT NOT NULL,
    BookID INT NOT NULL,
    Quantity INT NOT NULL,
    FOREIGN KEY (OrderID) REFERENCES Sales.Orders(OrderID),
    FOREIGN KEY (BookID) REFERENCES Sales.Books(BookID)
);
GO

-- Payments Table (Encryption remains here!)
CREATE TABLE Sales.Payments (
    PaymentID INT IDENTITY PRIMARY KEY,
    CustomerID INT,
    CardNumberEncrypted VARBINARY(MAX) NOT NULL,
    ExpiryMonthEncrypted VARBINARY(MAX) NOT NULL,
    ExpiryYearEncrypted VARBINARY(MAX) NOT NULL,
    Amount DECIMAL(10,2),
    PaymentDate DATETIME DEFAULT GETDATE()
);
GO

-- 4. COLUMN ENCRYPTION (This still works in RDS!)
CREATE CERTIFICATE PaymentCert WITH SUBJECT = 'Payment Data Encryption';
GO
CREATE SYMMETRIC KEY PaymentKey WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE PaymentCert;
GO

-- 5. STORED PROCEDURES (Same as before)
CREATE OR ALTER PROCEDURE Sales.sp_AddPayment
    @CustomerID INT, @CardNumber NVARCHAR(20), @ExpiryMonth NVARCHAR(2), 
    @ExpiryYear NVARCHAR(4), @Amount DECIMAL(10,2)
AS
BEGIN
    OPEN SYMMETRIC KEY PaymentKey DECRYPTION BY CERTIFICATE PaymentCert;
    INSERT INTO Sales.Payments (CustomerID, CardNumberEncrypted, ExpiryMonthEncrypted, ExpiryYearEncrypted, Amount)
    VALUES (@CustomerID, 
            ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @CardNumber),
            ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @ExpiryMonth),
            ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @ExpiryYear),
            @Amount);
    CLOSE SYMMETRIC KEY PaymentKey;
END;
GO

-- ... [Include all other Logic Procedures: Register, Login, CreateOrder, etc.] ...
-- ... [COPY THEM FROM YOUR PREVIOUS init_db.sql] ...

-- 6. CODE SIGNING (Still works in RDS!)
CREATE CERTIFICATE PaymentSigningCert WITH SUBJECT = 'Payment Signing';
GO
CREATE USER PaymentSigningUser FROM CERTIFICATE PaymentSigningCert;
GO
GRANT CONTROL ON CERTIFICATE::PaymentCert TO PaymentSigningUser;
GRANT CONTROL ON SYMMETRIC KEY::PaymentKey TO PaymentSigningUser;
GO
ADD SIGNATURE TO Sales.sp_AddPayment BY CERTIFICATE PaymentSigningCert;
GO

-- 7. ROW-LEVEL SECURITY (Still works in RDS!)
CREATE OR ALTER FUNCTION Security.fn_OrderFilter(@UserID INT)
RETURNS TABLE WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_securitypredicate_result
    WHERE @UserID = CAST(SESSION_CONTEXT(N'UserID') AS INT)
    OR CAST(SESSION_CONTEXT(N'Role') AS NVARCHAR(20)) = 'Admin';
GO

CREATE SECURITY POLICY Security.OrderSecurityPolicy
ADD FILTER PREDICATE Security.fn_OrderFilter(UserID) ON Sales.Orders
WITH (STATE = ON);
GO

-- 8. PERMISSIONS
-- RDS has a Master User (e.g., 'admin'). We will create the App User.
CREATE LOGIN OnlineBookstoreApp WITH PASSWORD = 'AppPassword123!', CHECK_POLICY = OFF;
GO
CREATE USER OnlineBookstoreApp FOR LOGIN OnlineBookstoreApp;
GO

GRANT SELECT ON Sales.Books TO OnlineBookstoreApp;
GRANT EXECUTE ON SCHEMA::Application TO OnlineBookstoreApp;
GRANT EXECUTE ON SCHEMA::Sales TO OnlineBookstoreApp;
DENY INSERT, UPDATE ON Sales.Books TO OnlineBookstoreApp;
GO

-- 9. AUDITING (Modified for Cloud)
-- We cannot use C:\SQL_Audit. We use DB Audit which can be read via SQL.
USE master;
GO
-- Create Audit to Application Log (Viewable in RDS Console or via Query)
CREATE SERVER AUDIT Bookstore_Cloud_Audit
TO APPLICATION_LOG
WITH (ON_FAILURE = CONTINUE);
GO
ALTER SERVER AUDIT Bookstore_Cloud_Audit WITH (STATE = ON);
GO

USE OnlineBookstore;
GO
CREATE DATABASE AUDIT SPECIFICATION Audit_Payments
FOR SERVER AUDIT Bookstore_Cloud_Audit
ADD (SELECT ON Sales.Payments BY PUBLIC)
WITH (STATE = ON);
GO
