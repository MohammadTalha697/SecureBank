from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import sqlite3, hashlib, secrets, re, html
from crypto_utils import AESCipher, DESCipher

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

CSRF_TOKENS = {}

@app.after_request
def add_security_headers(response):
    mode = session.get('mode', 'secure')
    if mode == 'secure':
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self' fonts.googleapis.com fonts.gstatic.com; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' fonts.googleapis.com"
    else:
        response.headers['X-Frame-Options'] = 'ALLOWALL'
        response.headers['X-XSS-Protection'] = '0'
    return response

def get_db():
    conn = sqlite3.connect('securebank.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        balance REAL DEFAULT 5000.0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        amount REAL,
        note TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    admin_pass = hashlib.sha512("admin123".encode()).hexdigest()
    user_pass = hashlib.sha512("user123".encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                  ("admin", admin_pass, "admin", 99999.0))
        c.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                  ("alice", user_pass, "user", 5000.0))
        c.execute("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)",
                  ("bob", user_pass, "user", 3000.0))
    except:
        pass
    conn.commit()
    conn.close()

def generate_csrf_token():
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return token

def verify_csrf(token):
    return token == session.get('csrf_token')

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    mode = request.args.get('mode', 'secure')
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if mode == 'vulnerable':
            conn = get_db()
            hashed = hashlib.sha512(password.encode()).hexdigest()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
            try:
                user = conn.execute(query).fetchone()
            except Exception as e:
                error = f"SQL Error: {str(e)}"
                user = None
            conn.close()
            session['sqli_query'] = query
        else:
            hashed = hashlib.sha512(password.encode()).hexdigest()
            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                                (username, hashed)).fetchone()
            conn.close()
            session['sqli_query'] = None
        if user:
            session['user'] = user['username']
            session['role'] = user['role']
            session['mode'] = mode
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid credentials"
    return render_template('login.html', mode=mode, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (session['user'],)).fetchone()
    transactions = conn.execute(
        "SELECT * FROM transactions WHERE sender = ? OR receiver = ? ORDER BY timestamp DESC LIMIT 5",
        (session['user'], session['user'])).fetchall()
    conn.close()
    csrf_token = generate_csrf_token()
    return render_template('dashboard.html', user=user, transactions=transactions,
                           mode=session.get('mode', 'secure'), csrf_token=csrf_token)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    mode = session.get('mode', 'secure')
    if mode == 'secure':
        token = request.form.get('csrf_token')
        if not verify_csrf(token):
            return jsonify({'error': 'CSRF token invalid! Request blocked.', 'blocked': True}), 403
    receiver = request.form.get('receiver')
    amount = float(request.form.get('amount', 0))
    note = request.form.get('note', '')
    conn = get_db()
    sender_data = conn.execute("SELECT * FROM users WHERE username = ?", (session['user'],)).fetchone()
    receiver_data = conn.execute("SELECT * FROM users WHERE username = ?", (receiver,)).fetchone()
    if not receiver_data:
        conn.close()
        return jsonify({'error': 'Receiver not found'}), 400
    if sender_data['balance'] < amount:
        conn.close()
        return jsonify({'error': 'Insufficient balance'}), 400
    conn.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, session['user']))
    conn.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, receiver))
    conn.execute("INSERT INTO transactions (sender, receiver, amount, note) VALUES (?, ?, ?, ?)",
                 (session['user'], receiver, amount, note))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Transferred Rs.{amount} to {receiver}'})

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user' not in session:
        return redirect(url_for('login'))
    mode = session.get('mode', 'secure')
    if request.method == 'POST':
        content = request.form.get('content', '')
        if mode == 'secure':
            content = html.escape(content)
        conn = get_db()
        conn.execute("INSERT INTO messages (username, content) VALUES (?, ?)", (session['user'], content))
        conn.commit()
        conn.close()
    conn = get_db()
    msgs = conn.execute("SELECT * FROM messages ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template('messages.html', messages=msgs, mode=mode)

@app.route('/crypto')
def crypto():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('crypto.html', mode=session.get('mode', 'secure'))

@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.json
    text = data.get('text', '')
    algo = data.get('algo', 'aes')
    key = data.get('key', '')
    if algo == 'aes':
        if not key:
            key = AESCipher.generate_key()
        ct, iv = AESCipher.encrypt(text, key)
        return jsonify({'ciphertext': ct, 'iv': iv, 'key': key, 'algo': 'AES-128-CBC'})
    else:
        if not key:
            key = "deskey01"
        ct, iv = DESCipher.encrypt(text, key)
        return jsonify({'ciphertext': ct, 'iv': iv, 'key': key, 'algo': 'DES-CBC'})

@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.json
    ct = data.get('ciphertext', '')
    key = data.get('key', '')
    iv = data.get('iv', '')
    algo = data.get('algo', 'aes')
    try:
        if algo == 'aes':
            pt = AESCipher.decrypt(ct, key, iv)
        else:
            pt = DESCipher.decrypt(ct, key, iv)
        return jsonify({'plaintext': pt})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/admin')
def admin():
    if 'user' not in session or session.get('role') != 'admin':
        return render_template('error.html', message="Access Denied — Admins Only"), 403
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    all_tx = conn.execute("SELECT * FROM transactions ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template('admin.html', users=users, transactions=all_tx,
                           mode=session.get('mode', 'secure'))

@app.route('/api/hash', methods=['POST'])
def api_hash():
    data = request.json
    text = data.get('text', '')
    hashed = hashlib.sha512(text.encode()).hexdigest()
    return jsonify({'hash': hashed})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forge-csrf')
def forge_csrf():
    return render_template('forge_csrf.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)