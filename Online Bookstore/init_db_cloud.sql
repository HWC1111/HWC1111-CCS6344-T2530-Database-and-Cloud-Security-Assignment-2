USE master;
GO

-- 1. CLEANUP (Reset DB if retrying)
IF EXISTS (SELECT 1 FROM sys.databases WHERE name = 'OnlineBookstore')
BEGIN
    ALTER DATABASE OnlineBookstore SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE OnlineBookstore;
END
GO

-- 2. CREATE DATABASE
CREATE DATABASE OnlineBookstore;
GO

USE OnlineBookstore;
GO

-- 3. ENABLE TDE (Encryption at Rest)
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongMasterKeyPassword123!';
GO

USE master;
GO
CREATE CERTIFICATE BookstoreTDECert WITH SUBJECT = 'TDE Certificate';
GO

USE OnlineBookstore;
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE BookstoreTDECert;
GO
ALTER DATABASE OnlineBookstore SET ENCRYPTION ON;
GO

-- 4. CREATE TABLES & SCHEMA
CREATE SCHEMA Application;
GO
CREATE SCHEMA Sales;
GO
CREATE SCHEMA Security;
GO

CREATE TABLE Application.Users (
    UserID INT IDENTITY PRIMARY KEY,
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    Role NVARCHAR(20) NOT NULL
);
GO

CREATE TABLE Application.LoginTracking (
    Username NVARCHAR(50) PRIMARY KEY,
    FailedAttempts INT DEFAULT 0,
    LockoutEnd DATETIME NULL
);
GO

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

CREATE TABLE Sales.Books (
    BookID INT IDENTITY PRIMARY KEY,
    Title NVARCHAR(200),
    Author NVARCHAR(100),
    Price DECIMAL(10,2),
    Stock INT
);
GO

CREATE TABLE Sales.Orders (
    OrderID INT IDENTITY PRIMARY KEY,
    UserID INT,
    OrderDate DATETIME DEFAULT GETDATE(),
    TotalAmount DECIMAL(10,2),
    DiscountAmount DECIMAL(10,2),
    FOREIGN KEY (UserID) REFERENCES Application.Users(UserID)
);
GO

CREATE TABLE Sales.OrderItems (
    OrderItemID INT IDENTITY PRIMARY KEY,
    OrderID INT NOT NULL,
    BookID INT NOT NULL,
    Quantity INT NOT NULL,
    FOREIGN KEY (OrderID) REFERENCES Sales.Orders(OrderID),
    FOREIGN KEY (BookID) REFERENCES Sales.Books(BookID)
);
GO

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

-- 5. COLUMN ENCRYPTION SETUP
CREATE CERTIFICATE PaymentCert WITH SUBJECT = 'Payment Data Encryption';
GO
CREATE SYMMETRIC KEY PaymentKey WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE PaymentCert;
GO

-- 6. STORED PROCEDURES (Application Logic)
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

CREATE OR ALTER PROCEDURE Application.sp_RegisterUser
    @Username NVARCHAR(50), @PasswordHash NVARCHAR(255)
AS
BEGIN
    IF EXISTS (SELECT 1 FROM Application.Users WHERE Username = @Username) THROW 50005, 'Exists', 1;
    INSERT INTO Application.Users (Username, PasswordHash, Role) VALUES (@Username, @PasswordHash, 'User');
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_LoginUser
    @Username NVARCHAR(50)
AS
BEGIN
    SELECT UserID, Username, PasswordHash, Role FROM Application.Users WHERE Username = @Username;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_CheckLockout
    @Username NVARCHAR(50)
AS
BEGIN
    DECLARE @IsLocked BIT = 0;
    DECLARE @LockoutEnd DATETIME;
    SELECT @LockoutEnd = LockoutEnd FROM Application.LoginTracking WHERE Username = @Username;
    IF @LockoutEnd IS NOT NULL AND @LockoutEnd > GETDATE() SET @IsLocked = 1;
    ELSE UPDATE Application.LoginTracking SET FailedAttempts = 0, LockoutEnd = NULL WHERE Username = @Username;
    SELECT @IsLocked AS IsLocked;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_ReportLoginFailure
    @Username NVARCHAR(50)
AS
BEGIN
    IF NOT EXISTS (SELECT 1 FROM Application.LoginTracking WHERE Username = @Username)
        INSERT INTO Application.LoginTracking (Username, FailedAttempts) VALUES (@Username, 1);
    ELSE
        UPDATE Application.LoginTracking SET FailedAttempts = FailedAttempts + 1 WHERE Username = @Username;
    DECLARE @Failures INT;
    SELECT @Failures = FailedAttempts FROM Application.LoginTracking WHERE Username = @Username;
    IF @Failures >= 3 UPDATE Application.LoginTracking SET LockoutEnd = DATEADD(MINUTE, 15, GETDATE()) WHERE Username = @Username;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_ReportLoginSuccess
    @Username NVARCHAR(50)
AS
BEGIN
    DELETE FROM Application.LoginTracking WHERE Username = @Username;
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_CreateOrder
    @UserID INT, @TotalAmount DECIMAL(10,2), @DiscountAmount DECIMAL(10,2)
AS
BEGIN
    INSERT INTO Sales.Orders (UserID, TotalAmount, DiscountAmount) VALUES (@UserID, @TotalAmount, @DiscountAmount);
    SELECT SCOPE_IDENTITY();
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_AddOrderItem
    @OrderID INT, @BookID INT, @Quantity INT
AS
BEGIN
    INSERT INTO Sales.OrderItems (OrderID, BookID, Quantity) VALUES (@OrderID, @BookID, @Quantity);
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_DecreaseStock
    @BookID INT, @Quantity INT
AS
BEGIN
    UPDATE Sales.Books SET Stock = Stock - @Quantity WHERE BookID = @BookID AND Stock >= @Quantity;
    IF @@ROWCOUNT = 0 THROW 50006, 'Insufficient stock', 1;
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_InsertBook
    @Title NVARCHAR(200), @Author NVARCHAR(100), @Price DECIMAL(10,2), @Stock INT
AS
BEGIN
    INSERT INTO Sales.Books (Title, Author, Price, Stock) VALUES (@Title, @Author, @Price, @Stock);
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_GetUserOrders
AS
BEGIN
    SELECT OrderID, OrderDate, TotalAmount, DiscountAmount FROM Sales.Orders;
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_GetAllOrders
AS
BEGIN
    SELECT U.Username, O.OrderID, O.TotalAmount, O.DiscountAmount, O.OrderDate FROM Sales.Orders O JOIN Application.Users U ON O.UserID = U.UserID;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_IsMember
    @UserID INT
AS
BEGIN
    SELECT CASE WHEN EXISTS (SELECT 1 FROM Application.Members WHERE UserID = @UserID) THEN 1 ELSE 0 END AS IsMember;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_CreateAdmin @PasswordHash NVARCHAR(255) AS
BEGIN
    IF NOT EXISTS (SELECT 1 FROM Application.Users WHERE Username = 'admin')
        INSERT INTO Application.Users (Username, PasswordHash, Role) VALUES ('admin', @PasswordHash, 'Admin');
END;
GO
CREATE OR ALTER PROCEDURE Application.sp_GetUsers AS
BEGIN
    SELECT UserID, Username, Role FROM Application.Users WHERE Role = 'User';
END;
GO
CREATE OR ALTER PROCEDURE Application.sp_GetMembers AS
BEGIN
    SELECT U.Username, M.FullName, M.Email FROM Application.Members M JOIN Application.Users U ON M.UserID = U.UserID;
END;
GO


-- 7. CODE SIGNING
CREATE CERTIFICATE PaymentSigningCert WITH SUBJECT = 'Payment Signing';
GO
CREATE USER PaymentSigningUser FROM CERTIFICATE PaymentSigningCert;
GO
GRANT CONTROL ON CERTIFICATE::PaymentCert TO PaymentSigningUser;
GRANT CONTROL ON SYMMETRIC KEY::PaymentKey TO PaymentSigningUser;
GO
ADD SIGNATURE TO Sales.sp_AddPayment BY CERTIFICATE PaymentSigningCert;
GO

CREATE CERTIFICATE BookOpsCert WITH SUBJECT = 'Book Signing';
GO
CREATE USER BookOpsUser FROM CERTIFICATE BookOpsCert;
GO
GRANT INSERT, UPDATE ON Sales.Books TO BookOpsUser;
GO
ADD SIGNATURE TO Sales.sp_InsertBook BY CERTIFICATE BookOpsCert;
GO


-- 8. ROW-LEVEL SECURITY
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


-- 9. PERMISSIONS
USE master;
GO
CREATE LOGIN OnlineBookstoreApp WITH PASSWORD = 'AppPassword123!', CHECK_POLICY = OFF;
GO
USE OnlineBookstore;
GO
CREATE USER OnlineBookstoreApp FOR LOGIN OnlineBookstoreApp;
GO
GRANT SELECT ON Sales.Books TO OnlineBookstoreApp;
GRANT EXECUTE ON SCHEMA::Application TO OnlineBookstoreApp;
GRANT EXECUTE ON SCHEMA::Sales TO OnlineBookstoreApp;
DENY INSERT, UPDATE ON Sales.Books TO OnlineBookstoreApp;
GO


-- 10. AUDITING (LINUX PATH!)
USE master;
GO
-- We point to the linux path /var/opt/mssql/audit/ which we created in UserData
IF NOT EXISTS (SELECT * FROM sys.server_audits WHERE name = 'Bookstore_Audit')
BEGIN
    CREATE SERVER AUDIT Bookstore_Audit
    TO FILE (FILEPATH = '/var/opt/mssql/audit/')
    WITH (ON_FAILURE = CONTINUE);
    ALTER SERVER AUDIT Bookstore_Audit WITH (STATE = ON);
END
GO

USE OnlineBookstore;
GO
IF NOT EXISTS (SELECT * FROM sys.database_audit_specifications WHERE name = 'Audit_Payments')
BEGIN
    CREATE DATABASE AUDIT SPECIFICATION Audit_Payments
    FOR SERVER AUDIT Bookstore_Audit
    ADD (SELECT ON Sales.Payments BY PUBLIC)
    WITH (STATE = ON);
END
GO
