from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Secret key for flash messages and sessions

# Absolute path to the database
db_path = r'C:\Infrastructure&Cloud\login_app\database\users.db'

# Initialize the database if it doesn't exist
def init_db():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Fetch all registered users from the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users")
    users = cursor.fetchall()
    conn.close()

    return render_template('dashboard.html', username=username, users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            flash('Username already exists. Please choose a different one.', 'danger')
            conn.close()
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        # Insert new user into the database
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Settings route for changing password
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        # Verify old password
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], old_password):
            # Update password
            hashed_new_password = generate_password_hash(new_password)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
            conn.commit()
            conn.close()

            flash('Password updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Old password is incorrect. Please try again.', 'danger')

    return render_template('settings.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
