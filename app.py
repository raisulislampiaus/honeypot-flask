from flask import Flask, render_template, flash, request, redirect, url_for,session
from time import time
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# Hardcoded database configuration
dbconfig = {
    'user': 'root',
    'password': '',  # Replace with your MySQL password
    'host': '127.0.0.1',  # Replace with your database host
    'database': 'make',
    'auth_plugin': ''
}

def connect_db():
    try:
        return mysql.connector.connect(**dbconfig)
    except Error as e:
        print(f"Error: {e}")
        return None

app = Flask(__name__, template_folder="templates")

# Creates a secret key for sessions, if this was a real app this would need to be secure.
# This just allows Flask to track sessions. It is used in login() when the app Flashes "Incorrect Credentials".
app.secret_key = 'supersecretkey'

# Redirects index to login
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
        post(ipAddress=remoteIP, host=request.headers.get('host'), username=username, password=password, userAgent=request.user_agent.string)
        flash("Incorrect Credentials", 'danger')
        return render_template('login.html')
    else:
        remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
        get(ipAddress=remoteIP, host=request.headers.get('host'), userAgent=request.user_agent.string, location='index')
        return render_template('login.html')

# For any locations for /
@app.route('/<path:u_path>', methods=['GET', 'POST'])
def location(u_path):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
        post(ipAddress=remoteIP, host=request.headers.get('host'), username=username, password=password, userAgent=request.user_agent.string)
        flash("Incorrect Credentials", 'danger')
        return render_template('login.html')
    else:
        remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
        get(ipAddress=remoteIP, host=request.headers.get('host'), userAgent=request.user_agent.string, location=u_path)
        return render_template('login.html')

# Static login page
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
#         remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
#         post(ipAddress=remoteIP, host=request.headers.get('host'), username=username, password=password, userAgent=request.user_agent.string)
#         flash("Incorrect Credentials", 'danger')
#         return render_template('login.html')
#     else:
#         remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
#         get(ipAddress=remoteIP, host=request.headers.get('host'), userAgent=request.user_agent.string, location='login')
#         return render_template('login.html')

# Database component
def get(ipAddress, userAgent, location, host):
    if app.debug:
        return
    mydb = None
    cursor = None
    try:
        mydb = mysql.connector.connect(**dbconfig)
        cursor = mydb.cursor(buffered=True, dictionary=True)
        cursor.execute("SELECT * FROM addresses WHERE ipAddress=%s", (ipAddress,))
        if cursor.rowcount == 0:
            cursor.execute("INSERT INTO addresses (ipAddress) VALUES (%s)", (ipAddress,))
        cursor.execute("INSERT INTO loads (ipAddress, userAgent, location, date, host) VALUES (%s, %s, %s, %s, %s)", (ipAddress, userAgent, location, int(time()), host))
        mydb.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if cursor:
            cursor.close()
        if mydb:
            mydb.close()

def post(ipAddress, host, username, password, userAgent):
    if app.debug:
        return
    mydb = None
    cursor = None
    try:
        mydb = mysql.connector.connect(**dbconfig)
        cursor = mydb.cursor(buffered=True, dictionary=True)
        cursor.execute("SELECT * FROM addresses WHERE ipAddress=%s", (ipAddress,))
        if cursor.rowcount == 0:
            cursor.execute("INSERT INTO addresses (ipAddress) VALUES (%s)", (ipAddress,))
        cursor.execute("INSERT INTO login_attempts (ipAddress, username, password, userAgent, date, host) VALUES (%s, %s, %s, %s, %s, %s)", (ipAddress, username, password, userAgent, int(time()), host))
        mydb.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if cursor:
            cursor.close()
        if mydb:
            mydb.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            mydb = mysql.connector.connect(**dbconfig)
            cursor = mydb.cursor()

            # Insert user into the authors table
            cursor.execute("INSERT INTO authors (username, password, email) VALUES (%s, %s, %s)",
                           (username, hashed_password, email))
            mydb.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Error as e:
            flash(f"Error: {e}", 'danger')
        finally:
            if cursor:
                cursor.close()
            if mydb:
                mydb.close()

    return render_template('register.html')

# Login Route
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         try:
#             mydb = mysql.connector.connect(**dbconfig)
#             cursor = mydb.cursor(dictionary=True)

#             # Check if the user exists
#             cursor.execute("SELECT * FROM authors WHERE username=%s", (username,))
#             user = cursor.fetchone()

#             if user and check_password_hash(user['password'], password):
#                 session['user_id'] = user['id']
#                 session['username'] = user['username']
#                 session['is_admin'] = user['is_admin']
                
#                 if user['is_admin']:
#                     return redirect(url_for('admin_dashboard'))
#                 else:
#                     flash('You are not an admin.', 'danger')
#                     return redirect(url_for('login'))
#             else:
#                 flash('Invalid credentials. Please try again.', 'danger')

#         except Error as e:
#             flash(f"Error: {e}", 'danger')
#         finally:
#             if cursor:
#                 cursor.close()
#             if mydb:
#                 mydb.close()

#     return render_template('login.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
#     host = request.headers.get('host')
#     user_agent = request.user_agent.string

#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
        
#         # hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
#         # Log the login attempt
#         post(ipAddress=remoteIP, host=host, username=username, password=password, userAgent=user_agent)

#         try:
#             mydb = mysql.connector.connect(**dbconfig)
#             cursor = mydb.cursor(dictionary=True)

#             # Fetch the user from the database
#             cursor.execute("SELECT * FROM authors WHERE username = %s", (username,))
#             user = cursor.fetchone()

#             if user and check_password_hash(user['password'], password):
#                 # Store session information
#                 session['username'] = user['username']
#                 session['is_admin'] = user['is_admin']  # Add role to session

#                 # Check for admin or user role
#                 if user['is_admin']:
#                     return render_template('admin.html')  # Show the admin page
#                 else:
#                     return redirect(url_for('user_page'))  # Redirect to normal user page
#             else:
#                 flash("Incorrect Credentials", 'danger')
#                 return render_template('login.html')

#         except Exception as e:
#             flash(f"Error: {e}", 'danger')
#             return render_template('login.html')  # Ensure this return is present

#         finally:
#             if cursor:
#                 cursor.close()
#             if mydb:
#                 mydb.close()

#     else:
#         # Log the access to the login page
#         get(ipAddress=remoteIP, host=host, userAgent=user_agent, location='login')
#         return render_template('login.html')

login_attempts = {}

BLOCK_DURATION = timedelta(minutes=2)  # Block for 10 minutes
MAX_ATTEMPTS = 3  # Allow 5 failed attempts

@app.route('/login', methods=['GET', 'POST'])
def login():
    remoteIP = request.headers.get('X-Forwarded-For', request.remote_addr)
    host = request.headers.get('host')
    user_agent = request.user_agent.string

    # Check if the IP is blocked
    if remoteIP in login_attempts:
        attempts, first_attempt_time = login_attempts[remoteIP]
        if attempts >= MAX_ATTEMPTS and datetime.now() < first_attempt_time + BLOCK_DURATION:
            return render_template('blocked.html')  # Render the blocked page

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Log the login attempt
        post(ipAddress=remoteIP, host=host, username=username, password=password, userAgent=user_agent)

        try:
            mydb = mysql.connector.connect(**dbconfig)
            cursor = mydb.cursor(dictionary=True)

            # Fetch the user from the database
            cursor.execute("SELECT * FROM authors WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                # Login successful, reset attempts
                if remoteIP in login_attempts:
                    del login_attempts[remoteIP]

                # Store session information
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']  # Add role to session

                # Check for admin or user role
                if user['is_admin']:
                    return render_template('admin.html')  # Show the admin page
                else:
                    return redirect(url_for('user_page'))  # Redirect to normal user page
            else:
                flash("Incorrect Credentials", 'danger')

                # Handle failed attempt
                if remoteIP in login_attempts:
                    attempts, first_attempt_time = login_attempts[remoteIP]
                    login_attempts[remoteIP] = (attempts + 1, first_attempt_time)
                else:
                    login_attempts[remoteIP] = (1, datetime.now())

                # Check if the user should be blocked
                attempts, first_attempt_time = login_attempts[remoteIP]
                if attempts >= MAX_ATTEMPTS:
                    flash("Too many failed attempts. You are blocked for 10 minutes.", 'danger')
                    return render_template('blocked.html')  # Render blocked page

                return render_template('login.html')

        except Exception as e:
            flash(f"Error: {e}", 'danger')
            return render_template('login.html')

        finally:
            if cursor:
                cursor.close()
            if mydb:
                mydb.close()

    else:
        # Log the access to the login page
        get(ipAddress=remoteIP, host=host, userAgent=user_agent, location='login')
        return render_template('login.html')

# Admin Dashboard Route (Protected)
@app.route('/admin', methods=['GET'])
def admin_dashboard():
    if 'is_admin' in session and session['is_admin']:
        return render_template('admin.html')
    else:
        flash('You must be an admin to access this page.', 'danger')
        return redirect(url_for('login'))
 
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)  # Replace with your desired port if different
