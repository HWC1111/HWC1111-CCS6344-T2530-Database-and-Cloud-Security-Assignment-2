--1. Database Creation and Transparent Data Encryption (TDE)
USE master;
GO
CREATE DATABASE OnlineBookstore;
GO

USE OnlineBookstore;
GO
CREATE MASTER KEY
ENCRYPTION BY PASSWORD = 'Pa$$w0rd';
GO

USE master;
GO
CREATE CERTIFICATE BookstoreTDECert
WITH SUBJECT = 'TDE Certificate for OnlineBookstore';
GO

USE OnlineBookstore;
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE BookstoreTDECert;
GO
ALTER DATABASE OnlineBookstore SET ENCRYPTION ON;
GO

--2. Schema Design and Logical Separation
CREATE SCHEMA Application;
GO
CREATE SCHEMA Sales;
GO
CREATE SCHEMA Security;
GO

--3. Core Table Structures
CREATE TABLE Application.Users (
    UserID INT IDENTITY PRIMARY KEY,
    Username NVARCHAR(50) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    Role NVARCHAR(20) NOT NULL
);

CREATE TABLE Application.Members (
    MemberID INT IDENTITY PRIMARY KEY,
    UserID INT UNIQUE NOT NULL,
    FullName NVARCHAR(100),
    ICNumber NVARCHAR(20),
    Email NVARCHAR(100) MASKED WITH (FUNCTION = 'email()'),
    CreatedAt DATETIME DEFAULT GETDATE(),
    FOREIGN KEY (UserID) REFERENCES Application.Users(UserID)
);

CREATE TABLE Sales.Books (
    BookID INT IDENTITY PRIMARY KEY,
    Title NVARCHAR(200),
    Author NVARCHAR(100),
    Price DECIMAL(10,2),
    Stock INT
);

CREATE TABLE Sales.Orders (
    OrderID INT IDENTITY PRIMARY KEY,
    UserID INT,
    OrderDate DATETIME DEFAULT GETDATE(),
    TotalAmount DECIMAL(10,2),
    DiscountAmount DECIMAL(10,2),
    FOREIGN KEY (UserID) REFERENCES Application.Users(UserID)
);

CREATE TABLE Sales.OrderItems (
    OrderItemID INT IDENTITY PRIMARY KEY,
    OrderID INT NOT NULL,
    BookID INT NOT NULL,
    Quantity INT NOT NULL,
    FOREIGN KEY (OrderID) REFERENCES Sales.Orders(OrderID),
    FOREIGN KEY (BookID) REFERENCES Sales.Books(BookID)
);

--4. Column-Level Encryption for Payment Data
CREATE CERTIFICATE PaymentCert
WITH SUBJECT = 'Payment Data Encryption';
GO

CREATE SYMMETRIC KEY PaymentKey
WITH ALGORITHM = AES_256
ENCRYPTION BY CERTIFICATE PaymentCert;
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

--5. Secure Stored Procedure for Encrypted Payments
CREATE OR ALTER PROCEDURE Sales.sp_AddPayment
    @CustomerID INT,
    @CardNumber NVARCHAR(20),
    @ExpiryMonth NVARCHAR(2),
    @ExpiryYear NVARCHAR(4),
    @Amount DECIMAL(10,2)
AS
BEGIN
    SET NOCOUNT ON;

    OPEN SYMMETRIC KEY PaymentKey
    DECRYPTION BY CERTIFICATE PaymentCert;

    INSERT INTO Sales.Payments
    VALUES (
        @CustomerID,
        ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @CardNumber),
        ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @ExpiryMonth),
        ENCRYPTBYKEY(KEY_GUID('PaymentKey'), @ExpiryYear),
        @Amount,
        GETDATE()
    );

    CLOSE SYMMETRIC KEY PaymentKey;
END;
GO

--6. Code Signing for Secure Key Access
CREATE CERTIFICATE PaymentSigningCert
WITH SUBJECT = 'Payment Procedure Signing';
GO

CREATE USER PaymentSigningUser
FROM CERTIFICATE PaymentSigningCert;
GO

GRANT CONTROL ON CERTIFICATE::PaymentCert TO PaymentSigningUser;
GRANT CONTROL ON SYMMETRIC KEY::PaymentKey TO PaymentSigningUser;
GO

ADD SIGNATURE
TO Sales.sp_AddPayment
BY CERTIFICATE PaymentSigningCert;
GO

--7. Row-Level Security (RLS)
CREATE OR ALTER FUNCTION Security.fn_OrderFilter (@UserID INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
(
    SELECT 1 AS fn_securitypredicate_result
    WHERE
        CAST(SESSION_CONTEXT(N'Role') AS NVARCHAR(20)) = 'Admin'
        OR
        @UserID = CAST(SESSION_CONTEXT(N'UserID') AS INT)
);
GO

CREATE SECURITY POLICY Security.OrderSecurityPolicy
ADD FILTER PREDICATE Security.fn_OrderFilter(UserID)
ON Sales.Orders
WITH (STATE = ON);
GO

--8. Least-Privilege Access Control
USE master;
GO
CREATE LOGIN OnlineBookstoreApp
WITH PASSWORD = 'Pa$$w0rd';
GO

USE OnlineBookstore;
GO
CREATE USER OnlineBookstoreApp FOR LOGIN OnlineBookstoreApp;
GO

GRANT SELECT ON Sales.Books TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_AddPayment TO OnlineBookstoreApp;
GO

--9. Auditing
CREATE SERVER AUDIT Bookstore_Audit
TO FILE (FILEPATH = 'C:\SQL_Audit\');
GO
ALTER SERVER AUDIT Bookstore_Audit WITH (STATE = ON);
GO

CREATE DATABASE AUDIT SPECIFICATION Audit_Payments
FOR SERVER AUDIT Bookstore_Audit
ADD (SELECT ON Sales.Payments BY PUBLIC)
WITH (STATE = ON);
GO

--10. Stored Procedures for Secure Application Access
CREATE OR ALTER PROCEDURE Application.sp_LoginUser
    @Username NVARCHAR(50)
AS
BEGIN
    SELECT UserID, Username, PasswordHash, Role
    FROM Application.Users
    WHERE Username = @Username;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_RegisterUser
    @Username NVARCHAR(50),
    @PasswordHash NVARCHAR(255)
AS
BEGIN
    IF EXISTS (SELECT 1 FROM Application.Users WHERE Username = @Username)
        RAISERROR ('Username already exists', 16, 1);

    INSERT INTO Application.Users (Username, PasswordHash, Role)
    VALUES (@Username, @PasswordHash, 'User');
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_IsMember
    @UserID INT
AS
BEGIN
    IF EXISTS (SELECT 1 FROM Application.Members WHERE UserID = @UserID)
        SELECT 1 AS IsMember;
    ELSE
        SELECT 0 AS IsMember;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_RegisterMember
    @UserID INT,
    @FullName NVARCHAR(100),
    @ICNumber NVARCHAR(20),
    @Email NVARCHAR(100)
AS
BEGIN
    INSERT INTO Application.Members (UserID, FullName, ICNumber, Email)
    VALUES (@UserID, @FullName, @ICNumber, @Email);
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_CreateOrder
    @UserID INT,
    @TotalAmount DECIMAL(10,2),
    @DiscountAmount DECIMAL(10,2)
AS
BEGIN
    INSERT INTO Sales.Orders (UserID, TotalAmount, DiscountAmount)
    VALUES (@UserID, @TotalAmount, @DiscountAmount);

    SELECT SCOPE_IDENTITY() AS OrderID;
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_GetUserOrders
AS
BEGIN
    SELECT OrderID, OrderDate, TotalAmount, DiscountAmount
    FROM Sales.Orders;
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_GetUsers
AS
BEGIN
    SELECT UserID, Username, Role
    FROM Application.Users
    WHERE Role = 'User';
END;
GO

CREATE OR ALTER PROCEDURE Application.sp_GetMembers
AS
BEGIN
    SELECT U.Username, M.FullName, M.Email
    FROM Application.Members M
    JOIN Application.Users U ON M.UserID = U.UserID;
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_GetAllOrders
AS
BEGIN
    SELECT U.Username, O.OrderID, O.TotalAmount, O.DiscountAmount, O.OrderDate
    FROM Sales.Orders O
    JOIN Application.Users U ON O.UserID = U.UserID;
END;
GO

USE OnlineBookstore;
GO

CREATE OR ALTER PROCEDURE Sales.sp_AddOrderItem
    @OrderID INT,
    @BookID INT,
    @Quantity INT
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO Sales.OrderItems (OrderID, BookID, Quantity)
    VALUES (@OrderID, @BookID, @Quantity);
END;
GO


USE OnlineBookstore;
GO

CREATE OR ALTER PROCEDURE Sales.sp_DecreaseStock
    @BookID INT,
    @Quantity INT
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE Sales.Books
    SET Stock = Stock - @Quantity
    WHERE BookID = @BookID
      AND Stock >= @Quantity;

    IF @@ROWCOUNT = 0
    BEGIN
        RAISERROR ('Insufficient stock', 16, 1);
    END
END;
GO

USE OnlineBookstore;
GO

CREATE OR ALTER PROCEDURE Sales.sp_InsertBook
    @Title NVARCHAR(200),
    @Author NVARCHAR(100),
    @Price DECIMAL(10,2),
    @Stock INT
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO Sales.Books (Title, Author, Price, Stock)
    VALUES (@Title, @Author, @Price, @Stock);
END;
GO

CREATE OR ALTER PROCEDURE Sales.sp_GetUserOrders
AS
BEGIN
    SELECT OrderID, OrderDate, TotalAmount, DiscountAmount
    FROM Sales.Orders;
END;
GO

USE OnlineBookstore;
GO

USE OnlineBookstore;
GO

CREATE OR ALTER PROCEDURE Application.sp_CreateAdmin
    @Username NVARCHAR(50),
    @PasswordHash NVARCHAR(255)
AS
BEGIN
    SET NOCOUNT ON;

    IF NOT EXISTS (
        SELECT 1 FROM Application.Users WHERE Username = @Username
    )
    BEGIN
        INSERT INTO Application.Users (Username, PasswordHash, Role)
        VALUES (@Username, @PasswordHash, 'Admin');
    END
END;
GO


GRANT SELECT ON Sales.Books TO OnlineBookstoreApp;

GRANT EXECUTE ON Application.sp_RegisterUser TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_RegisterMember TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_LoginUser TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_IsMember TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_GetUserOrders TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_CreateAdmin TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_GetUsers TO OnlineBookstoreApp;
GRANT EXECUTE ON Application.sp_GetMembers TO OnlineBookstoreApp;

GRANT EXECUTE ON Sales.sp_CreateOrder TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_AddOrderItem TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_DecreaseStock TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_GetAllOrders TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_AddPayment TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_InsertBook TO OnlineBookstoreApp;
GRANT EXECUTE ON Sales.sp_GetUserOrders TO OnlineBookstoreApp;
GO
