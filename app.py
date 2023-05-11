"""The following renders a website abotu British Shorthair cats
and generates the current date that the user is viewing the site on."""
from datetime import datetime
import re
import json
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect
from flask import url_for, session, flash, get_flashed_messages
from passlib.hash import sha256_crypt
app = Flask(__name__)
app.secret_key = '76502c46454c0d78ab5f4694dc5ae5bd9505a8f354c8ed23de56d0f9c9cf6aa6'
app.config['SECRET_KEY'] = 'mysecretkey'
USERS_FILE = 'users.json'
# Create the users file if it doesn't exist
try:
    with open(USERS_FILE, 'r', encoding="utf8") as database:
        users = json.load(database)
except FileNotFoundError:
    with open(USERS_FILE, 'w', encoding="utf8") as database:
        users = {}
        json.dump(users, database)
def validate_password(password):
    """this function validates the user's password"""
    #Check the password length
    if len(password) < 12:
        return False
    #Check for the one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False
    #Check for the one lowercase letter
    if not re.search(r'[a-z]', password):
        return False
    #Check for the 1 number
    if not re.search(r'\d', password):
        return False
    #Check for the one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True
@app.route('/')
def index():
    """Generates the first page the user will fall on when they visit the site."""
    return render_template('index.html')
@app.route('/personality.html')
def personality():
    """Generates the personality page of the cats"""
    return render_template('personality.html')
### HOME PAGE #################################################################
@app.route('/index.html')
def home():
    """Generates the home page"""
    return render_template('index.html')
### GALLERY PAGE #################################################################
@app.route('/gallery.html', methods=['GET', 'POST'])
# @login_required ########################################
# if the user is not logged in, they will be redirected to the login page
# if the user logs in, they can view the gallery
def gallery():
    """Generates the gallery template html page"""
    # Check if user is logged in
    if not session.get('logged_in'):
        # Set a flash message to be displayed on the login page
        flash('You must log in to access the gallery.')
        # Redirect to the login page
        return redirect(url_for('login'))
    return render_template('gallery.html')
### LOGIN PAGE #################################################################
# Set up logging
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
log_handler = RotatingFileHandler('login.log', maxBytes=100000, backupCount=1)
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)
@app.route('/login.html', methods=['GET', 'POST'])
def login():
    """Generates the login template html page"""
    flash_messages = get_flashed_messages()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Get the user's hashed password from the dictionary
        hashed_password = users.get(username)
        if hashed_password:
            # Verify the password using Passlib
            if sha256_crypt.verify(password, hashed_password):
                # Add code here to log the user in
                session['username'] = username
                session['logged_in'] = True
                success = 'You have logged in successfully.'
                return render_template('login.html',
                success = success,
                visibility = 'visible',
                flash_messages=flash_messages)
            error = 'Invalid username or password.'
            app.logger.warning(f'Failed login attempt: invalid username or password"{username}" from {request.remote_addr}')
            return render_template('login.html', error = error, display='block')
        error = 'Invalid username or password.'
        app.logger.warning(f'Failed login attempt: invalid username or password"{username}" from {request.remote_addr}')
        return render_template('login.html', error = error, display='block',
                            flash_messages=flash_messages)
    return render_template('login.html', flash_messages=flash_messages)
### REGISTER PAGE #################################################################
@app.route('/register.html', methods=['GET','POST'])
def register():
    """Generates the login template html page"""
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        # Check if the user already exists in the file
        if username in users:
            error = 'Username already exists.'
            return render_template('register.html', error = error, display = 'block')
        if email in users:
            error = 'Email already exists.'
            return render_template('register.html', error = error, display = 'block')
        if password != confirm_password:
            error  = 'Passwords do not match'
            return render_template('register.html', error = error, display = 'block')
        if not validate_password(password):
            error = ('Password must have 1 uppercase character, '
                    '1 lowercase character, '
                    '1 number, '
                    'and 1 special character.')
            return render_template('register.html', error = error, display = 'block')
        # save the user's information to a database or other storage mechanism
        # Hash the password using Passlib
        hashed_password = sha256_crypt.hash(password)
        # Insert the user into the file
        users[username] = hashed_password
        with open(USERS_FILE, 'w', encoding="utf8") as data:
            json.dump(users, data)
        confirmation = 'You have successfully registered.'
        return render_template('register.html', confirmation = confirmation, visibility = 'visible')
    return render_template('register.html')
### LOG OUT PAGE #################################################################
@app.route('/logout.html', methods=['GET','POST'])
def logout():
    """Log out the user from the session."""
    # Clear user session
    session.clear()
    # Redirect to login page
    return render_template('logout.html')
@app.context_processor
def date_now():
    """
    This function is used to insert the current date into the html template.
    """
    today = datetime.now()
    return {'today': today.strftime("%m/%d/%y")}
### ACCOUNT PAGE #########################################################################
@app.route('/account.html', methods=['GET','POST'])
def account():
    """Shows the user's account so that they can reset their password."""
    # Make sure the user logs in before entering the account page.
    # Read common Passwords txt file and store in variable for use
    with open('CommonPassword.txt', encoding="utf8") as file:
        common_passwords = file.read().splitlines()
    # make sure user is logged in to view page
    if not session.get('logged_in'):
        flash('You must log in to access the account page.')
        # Redirect to the login page
        return redirect(url_for('login'))
    # Check if the entered current-password exist
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        username = session['username']
        hashed_current_password = users.get(username)
        # Catch all errors that can arise from an invalid current password or new password entry.
        if hashed_current_password:
            if sha256_crypt.verify(current_password, hashed_current_password):
                if new_password != confirm_new_password:
                    error = 'Passwords do not match.'
                    return render_template('account.html',username = session['username'],error = error,display = 'block')
                # Check if new password matches a password on CommonPassword.txt
                if new_password in common_passwords:
                    error = 'Password is too common. Please create a different password.'
                    return render_template('account.html',username = session['username'], error = error, display = 'block')
                if not validate_password(new_password):
                    error = ('Password must have 1 uppercase character, '
                    '1 lowercase character, '
                    '1 number, '
                    'and 1 special character.')
                    return render_template('account.html',username = session['username'], error = error, display = 'block')
                # Hash and store new password
                hashed_new_password = sha256_crypt.hash(new_password)
                users[username] = hashed_new_password
                with open(USERS_FILE, 'w', encoding="utf8") as data:
                    json.dump(users, data)
                    confirmation = 'Password has been changed.'
                    return render_template('account.html', username = session['username'],confirmation = confirmation, visibility = 'visible')
            error = 'Current password is incorrect.'
            return render_template('account.html', username = session['username'], error = error, display = 'block')
    return render_template('account.html', username = session['username'])
if __name__ == "__main__":
    app.run(debug=True)
    