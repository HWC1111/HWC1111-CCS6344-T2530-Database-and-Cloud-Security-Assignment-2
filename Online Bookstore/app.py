from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from decimal import Decimal
import db

app = Flask(__name__)
app.secret_key = "supersecretkey"

# HELPERS
def admin_only():
    return session.get("role") == "Admin"

def set_rls_context(cursor):
    cursor.execute(
        "EXEC sp_set_session_context N'UserID', ?",
        (session["user_id"],)
    )
    cursor.execute(
        "EXEC sp_set_session_context N'Role', ?",
        (session["role"],)
    )

def is_member(user_id):
    if not user_id or session.get("role") != "User":
        return False

    cursor = db.get_connection().cursor()
    result = cursor.execute(
        "EXEC Application.sp_IsMember ?",
        (user_id,)
    ).fetchone()

    return result and result.IsMember == 1

@app.context_processor
def inject_helpers():
    return dict(is_member=is_member)

# HOME
@app.route("/")
def home():
    cursor = db.get_connection().cursor()
    books = cursor.execute(
        "SELECT * FROM Sales.Books"
    ).fetchall()
    return render_template("books.html", books=books)

# REGISTER (STORED PROCEDURE)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        conn = db.get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "EXEC Application.sp_RegisterUser ?, ?",
                (
                    request.form["username"],
                    generate_password_hash(request.form["password"])
                )
            )
            conn.commit()
            return redirect("/login")

        except Exception:
            return render_template(
                "register.html",
                error="Username already exists."
            )

    return render_template("register.html")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        cursor = db.get_connection().cursor()

        user = cursor.execute(
            "EXEC Application.sp_LoginUser ?",
            (request.form["username"],)
        ).fetchone()

        if user and check_password_hash(user.PasswordHash, request.form["password"]):
            session.clear()
            session["user"] = user.Username
            session["user_id"] = user.UserID
            session["role"] = user.Role
            session["cart"] = {}

            return redirect("/admin/books" if user.Role == "Admin" else "/")

    return render_template("login.html")

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# MEMBER REGISTRATION
@app.route("/member/register", methods=["GET", "POST"])
def member_register():
    if session.get("role") != "User":
        abort(403)

    cursor = db.get_connection().cursor()

    result = cursor.execute(
        "EXEC Application.sp_IsMember ?",
        (session["user_id"],)
    ).fetchone()

    if result and result.IsMember == 1:
        return redirect("/")


    if request.method == "POST":
        cursor.execute(
            "EXEC Application.sp_RegisterMember ?, ?, ?, ?",
            (
                session["user_id"],
                request.form["fullname"],
                request.form["ic"],
                request.form["email"]
            )
        )
        cursor.connection.commit()
        return redirect("/")

    return render_template("member_register.html")

# CART
@app.route("/add_to_cart/<int:book_id>")
def add_to_cart(book_id):
    if session.get("role") != "User":
        abort(403)

    cursor = db.get_connection().cursor()
    book = cursor.execute(
        "SELECT Stock FROM Sales.Books WHERE BookID = ?",
        (book_id,)
    ).fetchone()

    if not book or book.Stock <= 0:
        return redirect("/")

    cart = session.get("cart", {})
    cart[str(book_id)] = cart.get(str(book_id), 0) + 1
    session["cart"] = cart

    return redirect("/")


@app.route("/cart")
def cart():
    if session.get("role") != "User":
        abort(403)

    cursor = db.get_connection().cursor()
    items, total = [], Decimal("0.00")

    for book_id, qty in session["cart"].items():
        book = cursor.execute(
            "SELECT * FROM Sales.Books WHERE BookID = ?",
            (book_id,)
        ).fetchone()

        subtotal = book.Price * qty
        total += subtotal
        items.append((book, qty, subtotal))

    return render_template("cart.html", items=items, total=total)

# CHECKOUT 
@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if session.get("role") != "User":
        abort(403)

    conn = db.get_connection()
    cursor = conn.cursor()

    set_rls_context(cursor)

    items, total = [], Decimal("0.00")

    for book_id, qty in session["cart"].items():
        book = cursor.execute(
            "SELECT BookID, Title, Price, Stock FROM Sales.Books WHERE BookID = ?",
            (book_id,)
        ).fetchone()

        if not book or book.Stock < qty:
            return redirect("/cart")

        subtotal = book.Price * qty
        total += subtotal
        items.append((book, qty, subtotal))

    discount = total * Decimal("0.10") if is_member(session["user_id"]) else Decimal("0.00")
    final_total = total - discount

    if request.method == "POST":
        try:
            order_id = cursor.execute(
                "EXEC Sales.sp_CreateOrder ?, ?, ?",
                (session["user_id"], final_total, discount)
            ).fetchone()[0]

            for book, qty, _ in items:
                cursor.execute(
                    "EXEC Sales.sp_AddOrderItem ?, ?, ?",
                    (order_id, book.BookID, qty)
                )

                cursor.execute(
                    "EXEC Sales.sp_DecreaseStock ?, ?",
                    (book.BookID, qty)
                )

            cursor.execute(
                """
                EXEC Sales.sp_AddPayment
                    @CustomerID = ?,
                    @CardNumber = ?,
                    @ExpiryMonth = ?,
                    @ExpiryYear = ?,
                    @Amount = ?
                """,
                (
                    session["user_id"],
                    request.form["card_num"],
                    request.form["exp_m"],
                    request.form["exp_y"],
                    final_total
                )
            )

            conn.commit() 
            
            session["cart"] = {}
            return redirect("/orders")

        except Exception as e:
            conn.rollback()
            print(f"Checkout Error: {e}") 
            raise e

    return render_template(
        "checkout.html",
        items=items,
        total=total,
        discount=discount,
        final_total=final_total
    )

# USER ORDERS
@app.route("/orders")
def orders():
    if session.get("role") != "User":
        abort(403)

    cursor = db.get_connection().cursor()
    set_rls_context(cursor)

    orders = cursor.execute(
        "EXEC Sales.sp_GetUserOrders"
    ).fetchall()


    return render_template("user_orders.html", orders=orders)

# ADMIN
@app.route("/admin/books", methods=["GET", "POST"])
def admin_books():
    if not admin_only():
        abort(403)

    cursor = db.get_connection().cursor()

    if request.method == "POST":
        cursor.execute(
            "EXEC Sales.sp_InsertBook ?, ?, ?, ?",
            (
                request.form["title"],
                request.form["author"],
                request.form["price"],
                request.form["stock"]
            )
        )
        cursor.connection.commit()

    books = cursor.execute(
        "SELECT * FROM Sales.Books"
    ).fetchall()

    return render_template("admin_books.html", books=books)


@app.route("/admin/users")
def admin_users():
    if not admin_only():
        abort(403)

    users = db.get_connection().cursor().execute(
        "EXEC Application.sp_GetUsers"
    ).fetchall()

    return render_template("admin_users.html", users=users)


@app.route("/admin/members")
def admin_members():
    if not admin_only():
        abort(403)

    members = db.get_connection().cursor().execute(
        "EXEC Application.sp_GetMembers"
    ).fetchall()

    return render_template("admin_members.html", members=members)


@app.route("/admin/orders")
def admin_orders():
    if not admin_only():
        abort(403)

    cursor = db.get_connection().cursor()
    
    set_rls_context(cursor) 
    
    orders = cursor.execute("EXEC Sales.sp_GetAllOrders").fetchall()
    return render_template("admin_orders.html", orders=orders)

@app.route("/admin/orders/<int:order_id>")
def admin_order_details(order_id):
    if not admin_only():
        abort(403)

    cursor = db.get_connection().cursor()

    try:
        cursor.execute("EXEC sp_set_session_context @key=N'Role', @value=N'Admin'")

        order = cursor.execute(
            "EXEC Sales.sp_GetOrderDetails ?",
            (order_id,)
        ).fetchone()

        if not order:
            abort(404)

        items = cursor.execute(
            "EXEC Sales.sp_GetOrderItems ?",
            (order_id,)
        ).fetchall()

        return render_template(
            "admin_order_details.html",
            order=order,
            items=items
        )
    finally:
        cursor.close()

# MAIN
if __name__ == "__main__":
    app.run(debug=True)
