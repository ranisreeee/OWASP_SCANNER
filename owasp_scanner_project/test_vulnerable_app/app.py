#!/usr/bin/env python3
"""
Vulnerable Web Application for Testing
DO NOT USE IN PRODUCTION - This app contains intentional vulnerabilities
"""

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'vulnerable_secret_key_12345'

# Database setup
DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnerable.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                 (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT)''')
    
    # Insert test data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'test', 'test123', 'user')")
    conn.commit()
    conn.close()

init_db()

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .nav { background: #333; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
        .nav a { color: white; text-decoration: none; margin-right: 15px; }
        .nav a:hover { text-decoration: underline; }
        .vuln-box { border: 2px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 5px; background: #ffeaea; }
        input[type="text"], input[type="password"], textarea { width: 100%; padding: 8px; margin: 5px 0; }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .error { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/search">Search</a>
            <a href="/profile/1">Profile</a>
            <a href="/admin">Admin</a>
            <a href="/ping">Ping</a>
            <a href="/comment">Comments</a>
        </div>
        <h1>🔓 Vulnerable Test Application</h1>
        <p style="color: #e74c3c;"><strong>WARNING:</strong> This application contains intentional security vulnerabilities.</p>
        {{ content | safe }}
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    content = """
    <h2>Available Vulnerabilities</h2>
    <div class="vuln-box">
        <h3>A01: Broken Access Control</h3>
        <ul>
            <li><a href="/admin">Unprotected Admin Panel</a></li>
            <li><a href="/profile/1">IDOR - View any user's profile</a></li>
        </ul>
    </div>
    <div class="vuln-box">
        <h3>A03: Injection</h3>
        <ul>
            <li><a href="/search">SQL Injection in Search</a></li>
            <li><a href="/comment">XSS in Comments</a></li>
            <li><a href="/ping">Command Injection</a></li>
        </ul>
    </div>
    """
    return render_template_string(BASE_TEMPLATE, content=content)

# A03: SQL Injection
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        # VULNERABLE: String concatenation in SQL
        c.execute(f"SELECT * FROM users WHERE username LIKE '%{query}%'")
        results = c.fetchall()
    except Exception as e:
        results = []
        error = str(e)
    
    conn.close()
    
    html = f"""
    <h2>User Search (SQL Injection)</h2>
    <form method="get">
        <input type="text" name="q" value="{query}" placeholder="Search users...">
        <button type="submit">Search</button>
    </form>
    <p>Try: <code>' OR '1'='1</code></p>
    """
    
    if query:
        html += f"<h3>Results for: {query}</h3>"
        if results:
            html += "<table><tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>"
            for row in results:
                html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"
            html += "</table>"
        else:
            html += f"<p class='error'>No results</p>"
            if 'error' in locals():
                html += f"<p class='error'>Error: {error}</p>"
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A03: XSS
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    comments = []
    
    if request.method == 'POST':
        # VULNERABLE: No output encoding
        comment_text = request.form.get('comment', '')
        comments.append(comment_text)
    
    html = """
    <h2>Comments (XSS)</h2>
    <form method="post">
        <textarea name="comment" placeholder="Enter comment..."></textarea>
        <button type="submit">Post Comment</button>
    </form>
    <p>Try: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
    <h3>Comments:</h3>
    """
    
    for c in comments:
        # VULNERABLE: Direct output
        html += f"<div>{c}</div>"
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A03: Command Injection
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ""
    if request.method == 'POST':
        host = request.form.get('host', '')
        
        # VULNERABLE: Direct command execution
        try:
            result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5).decode()
        except Exception as e:
            result = str(e)
    
    html = f"""
    <h2>Network Diagnostics (Command Injection)</h2>
    <form method="post">
        <input type="text" name="host" placeholder="Enter IP or hostname">
        <button type="submit">Ping</button>
    </form>
    <p>Try: <code>127.0.0.1; cat /etc/passwd</code> or <code>127.0.0.1 | whoami</code></p>
    <pre>{result}</pre>
    """
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A01: IDOR
@app.route('/profile/<int:user_id>')
def profile(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        html = f"""
        <h2>User Profile</h2>
        <table>
            <tr><td>ID</td><td>{user[0]}</td></tr>
            <tr><td>Username</td><td>{user[1]}</td></tr>
            <tr><td>Password</td><td>{user[2]}</td></tr>
            <tr><td>Role</td><td>{user[3]}</td></tr>
        </table>
        <p class="error">Try changing the ID in the URL!</p>
        """
    else:
        html = "<p class='error'>User not found</p>"
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A01: Admin without auth
@app.route('/admin')
def admin():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    
    html = """
    <h2>Admin Panel (No Authentication Required!)</h2>
    <table>
        <tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th></tr>
    """
    for user in users:
        html += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td>{user[2]}</td><td>{user[3]}</td></tr>"
    html += "</table>"
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A07: Login with issues
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULNERABLE: SQL Injection
        c.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            return redirect('/')
        else:
            # VULNERABLE: User enumeration
            c = sqlite3.connect(DB_PATH).cursor()
            c.execute(f"SELECT * FROM users WHERE username = '{username}'")
            if c.fetchone():
                error = "Password is incorrect"
            else:
                error = "User does not exist"
    
    html = f"""
    <h2>Login</h2>
    <form method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    {f"<p class='error'>{error}</p>" if error else ""}
    <p>Valid: admin/admin123, user/password, test/test123</p>
    """
    
    return render_template_string(BASE_TEMPLATE, content=html)

# A05: Exposed files
@app.route('/.env')
def env_file():
    return """
    DB_HOST=localhost
    DB_USER=admin
    DB_PASSWORD=super_secret_password_123
    API_KEY=sk-1234567890abcdef
    SECRET_KEY=my_secret_key
    AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
    """

@app.route('/config')
def config():
    return {
        "debug": True,
        "database": "sqlite:///vulnerable.db",
        "secret_key": "vulnerable_secret_key_12345",
        "admin_password": "admin123"
    }

# Missing security headers
@app.after_request
def after_request(response):
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    response.headers['X-Powered-By'] = 'PHP/7.4.3'
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("Vulnerable Test Application")
    print("=" * 60)
    print("Access the app at: http://127.0.0.1:5000")
    print("DO NOT use in production!")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)