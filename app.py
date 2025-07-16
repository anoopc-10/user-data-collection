from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            phone TEXT NOT NULL
        )
    ''')
    
    # Create admin table for authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Create default admin user (username: admin, password: admin123)
    default_password = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO admin (username, password_hash) 
        VALUES (?, ?)
    ''', ('admin', default_password))
    
    conn.commit()
    conn.close()

def verify_password(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute('SELECT id FROM admin WHERE username = ? AND password_hash = ?', 
                   (username, password_hash))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Initialize database when app starts
init_db()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if verify_password(username, password):
            session['logged_in'] = True
            session['username'] = username
            return jsonify({'success': True, 'message': 'Login successful'})
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    data = request.json
    name = data.get('name')
    address = data.get('address')
    phone = data.get('phone')
    
    if not all([name, address, phone]):
        return jsonify({'error': 'All fields are required'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (name, address, phone) VALUES (?, ?, ?)', 
                   (name, address, phone))
    conn.commit()
    conn.close()
    
    return jsonify({'message': 'User added successfully'})

@app.route('/search_user', methods=['GET'])
@login_required
def search_user():
    query = request.args.get('query', '')
    
    if not query:
        return jsonify({'error': 'Search query is required'}), 400
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT name, address, phone FROM users 
        WHERE name LIKE ? OR phone LIKE ?
    ''', (f'%{query}%', f'%{query}%'))
    
    results = cursor.fetchall()
    conn.close()
    
    users = [{'name': row[0], 'address': row[1], 'phone': row[2]} for row in results]
    return jsonify({'users': users})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)