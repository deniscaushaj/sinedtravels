from flask import Flask, make_response, redirect, render_template, request, send_file
import os
from hashlib import sha256
from base64 import b64encode, b64decode

app = Flask(import_name=__name__)

SECRET_COOKIE = "QUESTA STRINGA È SEGRETA"
SECRET_PASS = "TRENTATRE TRENTINI ENTRARONO TUTTI E TRENTATRE A TRENTO TROTTERELLANDO"

MENU = [
    ("Home", "/"),
    ("Viaggi", "/travels"),
    ("Pacchetti", "/bundles"),
    ("Assicurazioni", "/insurance"),
    ("Hotel e alloggi", "/stay"),
]
USERS_PATH = "users"
USER_COOKIE = "user"

def hash(s: str) -> str:
    return sha256(s.encode()).hexdigest()

def hash_with_secret(s: str) -> str:
    return hash(SECRET_COOKIE + s + SECRET_COOKIE)

def hash_with_secret_pass(s: str) -> str:
    return hash(SECRET_PASS + s + SECRET_PASS)

def encode_user_cookie(username: str) -> str:
    return f"{b64encode(username.encode()).decode()}.{hash_with_secret(username)}"

def decode_user_cookie(cookie: str) -> str:
    username_b64, secret_hash = cookie.split(".")
    return b64decode(username_b64).decode(), secret_hash

def get_user_file(username: str) -> str:
    return os.path.join(USERS_PATH, username)

def request_username_password_hash():
    return request.form["username"], hash_with_secret_pass(request.form["password"])

@app.route("/signin", methods=["POST", "GET"])
def signin():
    if request.method == "GET":
        return render_template("signin.html")
    username, password_hash = request_username_password_hash()
    if not os.path.exists(USERS_PATH):
        os.makedirs(USERS_PATH, exist_ok=True)
    fn = get_user_file(username)
    if os.path.exists(fn):
        return render_template("signin.html", error=f"Lo username {username} è già esistente")
    try:
        with open(fn, "w") as f:
            f.write(password_hash)
    except:
        return render_template("signin.html", error="Errore interno. Riprova.")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username, password_hash = request_username_password_hash()
    fn = get_user_file(username)
    try:
        with open(fn) as f:
            real_password_hash = f.read()
    except:
        return render_template("login.html", error="Username non esistente")
    
    if real_password_hash != password_hash:
        return render_template("login.html", error="Password errata")

    resp = make_response(redirect("/"))
    resp.set_cookie(USER_COOKIE, encode_user_cookie(username))
    return resp

def login_username():
    if USER_COOKIE not in request.cookies:
        return None
    username, secret_hash = decode_user_cookie(request.cookies[USER_COOKIE])
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
    resp.set_cookie(USER_COOKIE, "", expires=0)
    return resp

@app.route("/static/RelazioneReti.pdf", methods=["GET"])
def download():
    return send_file("static/RelazioneReti.pdf", as_attachment=True)

app.run()