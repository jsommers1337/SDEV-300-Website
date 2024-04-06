"""this program uses Flask to generate a web page"""
import csv
import re
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = "asdf"
PASSWORD_FILE = "password_file.txt"
LOG_FILE = "logfile.txt"
COMMON_PASSWORDS = "CommonPassword.txt"
LOGGED_IN = False

logging.basicConfig(filename='text.log', level=logging.INFO)


@app.route('/')
def home():
    """this function generates the home page"""
    return render_template('home.html', title='Home', current_time=datetime.now())


@app.route('/about')
def about():
    """this function generates the about page"""
    return render_template('about.html', title='About This Site', current_time=datetime.now())


@app.route('/contact')
def contact():
    """this function generates the contact page"""
    return render_template('contact.html', title='Contact', current_time=datetime.now())


@app.route('/secret')
def secret():
    """this function generates a secret page as a reward for logging in"""
    if LOGGED_IN:
        return render_template('secret.html', title='Secret', current_time=datetime.now())
    return redirect(url_for('home'))


@app.route('/register', methods=['POST', 'GET'])
def register():
    """Function calls the register.html template and processes registration requests by
    validating that input meets required standards."""
    if request.method == 'GET':  # get / render the registration page for the user
        return render_template('register.html', style='home', title='Registration')
    # else request.method == 'POST' which means the user just
    # submitted/posted their registration page
    username = request.form['username']
    password = request.form['password']

    # Ensure username is a somewhat reasonable length
    if len(username) < 4:
        flash("Error - username must be 4 characters or longer")
        return redirect(url_for('register'))

    if get_password_if_registered(username) is not None:
        # Do: flash a message saying username already exists
        return render_template('register.html')

    if is_common_password(request.form['password']):
        flash("You entered a password that is too common. Try again.")
        return render_template('register.html')

    if not check_complexity(request.form['password']):  # Enforce password complexity
        flash("Error password does not meet the requirements of being 12 digits or more long "
              "and containing at least one of the following: 1 upper case, 1 lower case, 1 number"
              ", and 1 special character.")
        return redirect(url_for('register'))

    write_user_to_file(username, password)
    # Do: flash a message telling the user the registration was successful
    flash("Registration successful")
    return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
def login():
    """Function calls the register.html template and processes registration requests by
    validating that input meets required standards."""
    if request.method == 'POST':  # get / render the registration page for the user
        username = request.form['username']
        password = request.form['password']

        try:
            if sha256_crypt.verify(password, get_password_if_registered(username)):
                flash("Valid login.")
                global LOGGED_IN
                LOGGED_IN = True
                return redirect(url_for('secret'))
        except TypeError as error:
            flash("Invalid login. Try again.")
            ip = request.remote_addr
            logging.info('ip: %s' % ip)
            print(error.args)
            return redirect(url_for('login'))
        ip = request.remote_addr
        logging.info('ip: %s' % ip)
    # else request.method == 'POST' which means the user just
    # submitted/posted their registration page
    return render_template('login.html', style='home', title='Login')


@app.route('/update', methods=['POST', 'GET'])
def update():
    """Function calls the register.html template and processes registration requests by
    validating that input meets required standards."""
    if request.method == 'POST':  # get / render the registration page for the user
        username = request.form['username']
        password = request.form['password']
        new_password = request.form['new password']

        try:
            if sha256_crypt.verify(password, get_password_if_registered(username)) \
                    and check_complexity(new_password):
                flash("Valid information. Your password will now be updated.")
                delete_user_from_file(username)
                write_user_to_file(username, new_password)
                print("wrote")
                return redirect(url_for('secret'))
        except TypeError as error:
            flash("Error with username, old password, or new password. Try again.")
            ip = request.remote_addr
            logging.info('ip: %s' % ip)
            print(error.args)
            return redirect(url_for('update'))
        ip = request.remote_addr
        logging.info('ip: %s' % ip)
    # else request.method == 'POST' which means the user just
    # submitted/posted their registration page
    return render_template('update.html', style='home', title='Login')


def write_user_to_file(username, password):
    """ Write given username and password to the password file """
    pass_hash = sha256_crypt.hash(password)  # encrypt password before storing to file
    try:  # Add account info to account database
        with open(PASSWORD_FILE, 'a', encoding='UTF-8', newline='') as pass_file:
            writer = csv.writer(pass_file)
            writer.writerow([username, pass_hash])
    except FileNotFoundError as error:
        print("Could not find file called " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
        return redirect(url_for('register'))
    except Exception as error:
        print("Could not append to file " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
    return redirect(url_for('register'))


def delete_user_from_file(username):
    """ Write given username and password to the password file """
    try:  # Add account info to account database
        users = list()
        with open(PASSWORD_FILE, 'r+', encoding='UTF-8', newline='') as pass_file:
            reader = csv.reader(pass_file)
            for row in reader:
                users.append(row)
                for line in row:
                    if line == username:
                        users.remove(row)
        with open(PASSWORD_FILE, 'w', encoding='UTF-8', newline='') as pass_file:
            writer = csv.writer(pass_file)
            writer.writerows(users)
    except FileNotFoundError as error:
        print("Could not find file called " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
        return redirect(url_for('register'))
    except Exception as error:
        print("Could not append to file " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
    return redirect(url_for('register'))


def write_to_log_file(username, password, ip_addr):
    """ Write given username and password to the password file """
    pass_hash = sha256_crypt.hash(password)  # encrypt password before storing to file
    try:  # Add account info to account database
        with open(LOG_FILE, 'a', encoding='UTF-8', newline='') as pass_file:
            writer = csv.writer(pass_file)
            writer.writerow([username, pass_hash, ip_addr])
        return None
    except FileNotFoundError as error:
        print("Could not find file called " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
        return redirect(url_for('register'))
    except Exception as error:
        print("Could not append to file " + PASSWORD_FILE)
        print(error.args)  # all info about the error printed to the server for support to see/debug
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
    return redirect(url_for('register'))


def get_password_if_registered(username_input):
    """ Check if the given username does not already exist in our password file
    return none of the username does not exist; otherwise return the password for that user
    """
    try:
        with open(PASSWORD_FILE, "r", encoding='UTF-8') as users:
            for record in users:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                username, password = record.split(',')
                password = password.rstrip('\n')
                if username == username_input:
                    return password
    except FileNotFoundError as error:
        print('File not found: ' + PASSWORD_FILE)
        print(error.args)
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
        return redirect(url_for('home'))
    except Exception as error:
        print('No permissions to open this file or data in it not in correct format: ' +
              PASSWORD_FILE)
        print(error.args)
        # Do: flash a message to the user the account database
        # isn’t available right now and try back later or contact support
        flash("User database is not currently available. Try again later.")
        return redirect(url_for('home'))
        # decided better to do above than this abort: os.abort()
    return None


def check_complexity(password):
    """"this function uses regex to make sure the password conforms to the requirements"""
    # powerful regex that makes sure the password is 12 digits long,
    # has at least one upper case, at least one lower case, at least one number,
    # and at least one special character
    pattern = re.compile("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{12,}$")
    return bool(pattern.match(password))


def is_common_password(password):
    """this function returns true if the password is in the list of common passwords"""
    with open(COMMON_PASSWORDS, 'r', encoding="UTF-8") as common_passwords:
        read_content = common_passwords.read()
        if password in read_content:
            return True
        return False


if __name__ == '__main__':
    app.run(debug=True)
