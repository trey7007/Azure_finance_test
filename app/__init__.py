import os

import sqlite3 
from decouple import config

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd


# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure connection to SQLite database
def db_connection():
    connection = sqlite3.connect('finance.db')
    connection.row_factory = sqlite3.Row
    return connection

API_KEY = config('API_KEY')
# Make sure API key is set
if not API_KEY:
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        db = db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", [request.form.get("username")])
        
        
        rows = cur.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    #Allow them to register when opening register page
    if request.method == "GET":
        return render_template("register.html")
    
    #When submitting register form, validate it
    if request.method == "POST":

        name = request.form.get("username")
        # Ensure username was submitted
        if not name:
            return apology("must provide username", 403)
        
        # Query database for username
        db = db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", [name])
        rows = cur.fetchall()
        print(rows)

        # Ensure username does not exist
        if rows:
            return apology("Username already exists", 403)

        # Ensure password was submitted
        password = request.form.get("password")
        
        if not password:
            return apology("must provide password", 403)
        

        elif password != request.form.get("password2"):
            return apology("passwords must match", 403)

        #Add users username and password to DB
        
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", (name, generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)))

        db.commit()
        db.close()
        return render_template("login.html")
    


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
