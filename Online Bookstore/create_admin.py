from werkzeug.security import generate_password_hash
import db

conn = db.get_connection()
cursor = conn.cursor()

username = "superadmin"
password = "admin123"

cursor.execute(
    "EXEC Application.sp_CreateAdmin ?, ?",
    (username, generate_password_hash(password))
)

conn.commit()
conn.close()

print("Admin created:", username)
