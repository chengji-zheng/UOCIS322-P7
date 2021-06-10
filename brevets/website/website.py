# Adopted Based On website.example.py

import logging # Debug using
from urllib.parse import urlparse, urljoin
from flask import Flask, request, render_template, redirect, url_for, flash, abort, session
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user, UserMixin,
                         confirm_login, fresh_login_required)
from flask_wtf import FlaskForm as Form
from wtforms import BooleanField, StringField, PasswordField, validators
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)
import requests
import flask

class LoginForm(Form):
    username = StringField('Username', [
        validators.Length(min=2, max=25,
                          message=u"Huh, little too short for a username."),
        validators.InputRequired(u"Forget something?")])
    password = PasswordField("Password", [validators.Length(min=6, max=16, message=u"Huh, little too short for a password."), validators.InputRequired(u"Forget something?")])
    remember = BooleanField('Remember me')

class RegForm(Form):
    username = StringField('Username', [validators.Length(min=2, max=25, message=u"Huh, little too short for a username."), validators.InputRequired(u"Forget something?")])
    password = PasswordField("Password", [validators.Length(min=6, max=16, message=u"Huh, little too short for a password."), validators.InputRequired(u"Forget something?")])


def is_safe_url(target):
    """
    :source: https://github.com/fengsp/flask-snippets/blob/master/security/redirect_back.py
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


class User(UserMixin):
    def __init__(self, id, name, password, token):
        self.id = id
        self.name = name
        self.token = token 

app = Flask(__name__)
app.secret_key = "and the cats in the cradle and the silver spoon"

app.config.from_object(__name__)

login_manager = LoginManager()

login_manager.session_protection = "strong"

login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."

login_manager.refresh_view = "login"
login_manager.needs_refresh_message = (
    u"To protect your account, please reauthenticate to access this page."
)
login_manager.needs_refresh_message_category = "info"


@login_manager.user_loader

def load_user(user_id):
    """
    This callback is used to reload the user object from the user ID stored in the session. 
    It should take the unicode ID of a user, and return the corresponding user object. 
    """
    if "name" in session or "token" in session:
        if session["name"] == None or  session["token"] == None:
            return None
    return User(int(user_id), session["name"], session["token"])


login_manager.init_app(app)

def hash_password(password):
    return pwd_context.encrypt(password)

# Also, add a function to handle the logic for reg.
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegForm()
    if form.validate_on_submit() and request.method == "POST" and "username" in request.form and "password" in request.form:
        username = request.form["username"]
        password = request.form["password"]
        encryptedPW = hash_password(password)
        # Send a request to api and add to db.
        req = requests.get('http://restapi:5000/register/', {'username': username, 'password':  password})
        # Then checking the HTTP status code ...
        if req.status_code == 201:
            flash("SUCCESS!")
        flash("A MESSAGE HERE")
    
    return render_template("login.html", form=form)


# And fix the login under login.
@app.route("/login", methods=["GET", "POST"])
def login():
    # TODO Need to set sessions somewhere -- Using flask_login
    form = LoginForm()
    if form.validate_on_submit() and request.method == "POST" and "username" in request.form:
        username = request.form["username"]
        password = request.form["password"]
        encryptedPW = hash_password(password)
        # Not sure here ... 
        req = requests.get('http://restapi:5000/login/' + "?username=" + username + "&password=" + password)
        # If user in db
        if req.status_code == 200:
            remember = request.form.get("remember", "false") == "true"
            if login_user(User(username),remember=remember): # Double check here? later
                flash("Logged in!")
                flash("I'll remember you") if remember else None
                next = request.args.get("next")
                if not is_safe_url(next):
                    abort(400)
                return redirect(next or url_for('index'))
            else:
                flash("Sorry, but you could not log in.")
        else:
            flash(u"Invalid username.")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))



@app.route('/')
@app.route('/index')
def home():
    return render_template('website.html')

@app.route("/secret")
@login_required
def secret():
    flash("Welcome: {current_user.name}")
    return render_template("website.html")

@app.route('/listAll')
def listAll():
    fileType = request.args.get("format") # Get File Type fetched from clientSide
    qty = request.args.get("qty")    # get the quantity from the clientSide
    r = requests.get('http://restapi:5000/listAll' + "/" + fileType + "&token=" + current_user.token)
    return r.text

@app.route('/listOpenOnly')
def listOpenOnly():
    fileType = request.args.get("format") # Get File Type fetched from clientSide
    qty = request.args.get("qty", default=0, type=int)    # get the quantity from the clientSide
    r = requests.get('http://restapi:5000/listOpenOnly' + "/" + fileType + "?top=" + qty + "&token=" + current_user.token)
    return r.text

@app.route('/listCloseOnly')
def listCloseOnly():
    fileType = request.args.get("format") # Get File Type fetched from clientSide
    qty = request.args.get("qty", default=0, type=int)    # get the quantity from the clientSide
    r = requests.get('http://restapi:5000/listCloseOnly' + "/" + fileType + "?top=" + qty + "&token=" + current_user.token)
    return r.text


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
