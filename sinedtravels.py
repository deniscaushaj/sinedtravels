from flask import Flask, make_response, redirect, render_template, request, send_file
from crypt import methods
import os
from hashlib import sha256
from base64 import b64encode, b64decode

app = Flask(import_name=__name__)

SECRET = "QUESTA STRINGA È SEGRETA"

MENU = [
    ("Home", "/"),
    ("Viaggi", "/travels"),
    ("Pacchetti", "/bundles"),
    ("Assicurazioni", "/insurance"),
    ("Hotel e alloggi", "/stay"),
]

def hash(s):
    return sha256(s.encode()).hexdigest()

def hash_with_secret(s):
    return hash(SECRET + s + SECRET)

@app.route("/signin", methods=["POST", "GET"])
def signin():
    if request.method == "GET":
        return render_template("signin.html")
    username = request.form["username"]
    password = request.form["password"]
    password_hash = hash(password)
    if not os.path.exists("users"):
        os.makedirs("users", exist_ok=True)
    if os.path.exists(f"users/{username}"):
        return render_template("signin.html", error=f"Lo username {username} è già esistente")
    else:
        fn = os.path.join("users", username)
    try:
        with open(fn, "w") as f:
            f.write(password_hash)
    except:
        return render_template("signin.html", error="Errore interno. Riprova.")
    resp = make_response(redirect("/login"))
    return resp

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form["username"]
    password = request.form["password"]
    password_hash = hash(password)
    fn = os.path.join("users", username)
    try:
        with open(fn) as f:
            real_password_hash = f.read()
    except:
        return render_template("login.html", error="Username non esistente")
    
    if real_password_hash != password_hash:
        return render_template("login.html", error="Password errata")

    resp = make_response(redirect("/"))
    resp.set_cookie("user", f"{b64encode(username.encode()).decode()}.{hash_with_secret(username)}")
    return resp

def login_username():
    if "user" not in request.cookies:
        return None
    username_b64, secret_hash = request.cookies["user"].split(".")
    username = b64decode(username_b64).decode()
    if hash_with_secret(username) == secret_hash:
        return username
    else:
        return None

def check_login_and_render_template(template):
    username = login_username()
    if username is None:
        return redirect("/login")
    return render_template(template, menu_entries=MENU, username=username)


@app.route("/", methods=["GET"])
def home():
    return check_login_and_render_template("index.html")

@app.route("/travels", methods=["GET"])
def travels():
    return check_login_and_render_template("travels.html")

@app.route("/bundles", methods=["GET"])
def bundles():
    return check_login_and_render_template("bundles.html")

@app.route("/insurance", methods=["GET"])
def insurance():
    return check_login_and_render_template("insurance.html")
    
@app.route("/stay", methods=["GET"])
def stay():
    return check_login_and_render_template("stay.html")

@app.route("/logout", methods=["GET"])
def logout():
    resp = make_response(redirect("/login"))
    resp.set_cookie("user", "", expires=0)
    return resp

@app.route("/templates/sample.pdf", methods=["GET"])
def download():
    pdf = "templates/sample.pdf"
    return send_file(pdf, as_attachment=True)

app.run()