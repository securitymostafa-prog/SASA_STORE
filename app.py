
import os
import sqlite3
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "store.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            image TEXT
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            store_name TEXT NOT NULL,
            contact_email TEXT NOT NULL
        )
    """)

    admin = db.execute(
        "SELECT id FROM admins WHERE username = ?", ("sasa",)
    ).fetchone()

    if admin is None:
        db.execute(
            "INSERT INTO admins (username, password) VALUES (?, ?)",
            ("sasa", generate_password_hash("123456789"))
        )

    db.execute("""
        INSERT OR IGNORE INTO settings (id, store_name, contact_email)
        VALUES (1, 'SASA STORE', 'securitymostafa@gmail.com')
    """)

    db.commit()
    db.close()


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.context_processor
def inject_settings():
    db = get_db()
    settings = db.execute(
        "SELECT * FROM settings WHERE id = 1"
    ).fetchone()
    db.close()
    return {"site_settings": settings}


@app.route("/")
def index():
    db = get_db()
    products = db.execute(
        "SELECT * FROM products ORDER BY id DESC"
    ).fetchall()
    db.close()
    return render_template("index.html", products=products)


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        admin = db.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()
        db.close()

        if admin and check_password_hash(admin["password"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            return redirect(url_for("admin"))

        flash("اسم المستخدم أو كلمة المرور غير صحيحة", "error")

    return render_template("login.html")


@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    products = db.execute(
        "SELECT * FROM products ORDER BY id DESC"
    ).fetchall()
    db.close()
    return render_template("admin.html", products=products)


@app.route("/admin/add", methods=["POST"])
@admin_required
def add_product():
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    price_text = request.form.get("price", "").strip()
    image = request.files.get("image")

    if not name or not price_text:
        flash("اكتب اسم المنتج والسعر", "error")
        return redirect(url_for("admin"))

    try:
        price = float(price_text)
        if price < 0:
            raise ValueError
    except ValueError:
        flash("السعر غير صحيح", "error")
        return redirect(url_for("admin"))

    image_name = None

    if image and image.filename:
        if not allowed_file(image.filename):
            flash("صيغة الصورة غير مدعومة", "error")
            return redirect(url_for("admin"))

        safe_name = secure_filename(image.filename)
        image_name = secrets.token_hex(8) + "_" + safe_name
        image.save(os.path.join(UPLOAD_FOLDER, image_name))

    db = get_db()
    db.execute(
        """INSERT INTO products (name, description, price, image)
           VALUES (?, ?, ?, ?)""",
        (name, description, price, image_name)
    )
    db.commit()
    db.close()

    flash("تمت إضافة المنتج بنجاح", "success")
    return redirect(url_for("admin"))


@app.route("/admin/delete/<int:product_id>", methods=["POST"])
@admin_required
def delete_product(product_id):
    db = get_db()
    product = db.execute(
        "SELECT * FROM products WHERE id = ?", (product_id,)
    ).fetchone()

    if product:
        if product["image"]:
            image_path = os.path.join(UPLOAD_FOLDER, product["image"])
            if os.path.isfile(image_path):
                os.remove(image_path)

        db.execute("DELETE FROM products WHERE id = ?", (product_id,))
        db.commit()

    db.close()
    flash("تم حذف المنتج", "success")
    return redirect(url_for("admin"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def settings():
    db = get_db()

    if request.method == "POST":
        store_name = request.form.get("store_name", "").strip()
        email = request.form.get("contact_email", "").strip()

        if store_name and email:
            db.execute(
                """UPDATE settings
                   SET store_name = ?, contact_email = ?
                   WHERE id = 1""",
                (store_name, email)
            )
            db.commit()
            flash("تم حفظ الإعدادات", "success")
        else:
            flash("املأ جميع الحقول", "error")

        db.close()
        return redirect(url_for("settings"))

    current_settings = db.execute(
        "SELECT * FROM settings WHERE id = 1"
    ).fetchone()
    db.close()

    return render_template("settings.html", settings=current_settings)


@app.route("/admin/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.errorhandler(413)
def file_too_large(error):
    flash("حجم الصورة أكبر من 5 ميجابايت", "error")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
