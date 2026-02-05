from werkzeug.security import generate_password_hash
import db

conn = db.get_connection()
cursor = conn.cursor()

password = "admin123"
password_hash = generate_password_hash(password)

cursor.execute(
    "EXEC Application.sp_CreateAdmin ?",
    (password_hash,)
)

conn.commit()
conn.close()

print("Admin created: admin")
