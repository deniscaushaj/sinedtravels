from flask import Flask, make_response, redirect, render_template, request, send_file
import os
from hashlib import sha256
from base64 import b64encode, b64decode

app = Flask(import_name=__name__)

#Inizializzazione delle stringhe da usare per modificare i cookie e le password aumentando la sicurezza
SECRET_COOKIE = "QUESTA STRINGA È SEGRETA"
SECRET_PASS = "TRENTATRE TRENTINI ENTRARONO TUTTI E TRENTATRE A TRENTO TROTTERELLANDO"

#Lista delle pagine web e relativi indirizzi
MENU = [
    ("Home", "/"),
    ("Viaggi", "/travels"),
    ("Pacchetti", "/bundles"),
    ("Assicurazioni", "/insurance"),
    ("Hotel e alloggi", "/stay"),
]
USERS_PATH = os.path.join(os.path.dirname(__file__), "users")
USER_COOKIE = "user"

#Metodo per generare il SHA256 della stringa in input
def hash(s: str) -> str:
    return sha256(s.encode()).hexdigest()

#Hashing del cookie generato
def hash_with_secret(s: str) -> str:
    return hash(SECRET_COOKIE + s + SECRET_COOKIE)

#Hashing della password
def hash_with_secret_pass(s: str) -> str:
    return hash(SECRET_PASS + s + SECRET_PASS)

#Generazione del cookie
def encode_user_cookie(username: str) -> str:
    return f"{b64encode(username.encode()).decode()}.{hash_with_secret(username)}"

#Divisione del cookie in username e hash
def decode_user_cookie(cookie: str) -> str:
    username_b64, secret_hash = cookie.split(".")
    return b64decode(username_b64).decode(), secret_hash

#Restituisce lo username specificato
def get_user_file(username: str) -> str:
    return os.path.join(USERS_PATH, username)

#Ottiene username e password dal form
def request_username_password_hash():
    return request.form["username"], hash_with_secret_pass(request.form["password"])

#Gestione della registrazione
@app.route("/signin", methods=["POST", "GET"])
def signin():
    if request.method == "GET":
        return render_template("signin.html")
    username, password_hash = request_username_password_hash()

    #Controlla se esiste la caetella /users
    if not os.path.exists(USERS_PATH):
        os.makedirs(USERS_PATH, exist_ok=True)
    fn = get_user_file(username)

    #Controlla se lo username è già esistente
    if os.path.exists(fn):
        return render_template("signin.html", error=f"Lo username {username} è già esistente")
    try:
        with open(fn, "w") as f:
            f.write(password_hash)
    except:
        return render_template("signin.html", error="Errore interno. Riprova.")
    return redirect("/login")

#Gestione del login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username, password_hash = request_username_password_hash()
    fn = get_user_file(username)
    #Controlla se l'utente esiste
    try:
        with open(fn) as f:
            real_password_hash = f.read()
    except:
        return render_template("login.html", error="Username non esistente")
    
    #Controlla la password inserita coincide con quella della registrazione
    if real_password_hash != password_hash:
        return render_template("login.html", error="Password errata")

    #Se va tutto a buon fine l'utente viene reindirizzato alla homepage
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

#Metodo per la gestione della homepage
@app.route("/", methods=["GET"])
def home():
    return check_login_and_render_template("index.html")

#Metodo per la gestione della pagina dei viaggi
@app.route("/travels", methods=["GET"])
def travels():
    return check_login_and_render_template("travels.html")

#Metodo per la gestione della pagina dei pacchetti
@app.route("/bundles", methods=["GET"])
def bundles():
    return check_login_and_render_template("bundles.html")

#Metodo per la gestione della pagina delle assicurazioni
@app.route("/insurance", methods=["GET"])
def insurance():
    return check_login_and_render_template("insurance.html")
    
#Metodo per la gestione della pagina degli alloggi
@app.route("/stay", methods=["GET"])
def stay():
    return check_login_and_render_template("stay.html")

#Metodo per la gestione del logout
@app.route("/logout", methods=["GET"])
def logout():
    resp = make_response(redirect("/login"))
    resp.set_cookie(USER_COOKIE, "", expires=0)
    return resp

#Metodo per la gestione del download del pdf
@app.route("/static/RelazioneReti.pdf", methods=["GET"])
def download():
    return send_file("static/RelazioneReti.pdf", as_attachment=True)

app.run()