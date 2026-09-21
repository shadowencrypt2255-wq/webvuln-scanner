"""A deliberately vulnerable Flask app used ONLY to test this scanner
locally. Do not deploy this anywhere reachable from the internet.

Run: pip install flask && python testbed/vulnerable_app.py
Then scan: python main.py http://127.0.0.1:5000/ --i-have-authorization
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)
DB = "testbed.db"


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("DELETE FROM users")
    conn.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin')")
    conn.execute("INSERT INTO users (username, password) VALUES ('alice', 'password123')")
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <html><body>
    <h1>Testbed App</h1>
    <ul>
      <li><a href="/search?q=widgets">Search (SQL injection)</a></li>
      <li><a href="/comment">Comment form (Reflected XSS)</a></li>
      <li><a href="/login">Login (Broken authentication)</a></li>
    </ul>
    </body></html>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Intentionally vulnerable: string-concatenated SQL for demo purposes.
    query = f"SELECT username FROM users WHERE username LIKE '%{q}%'"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        body = "<br>".join(r[0] for r in rows)
    except sqlite3.OperationalError as exc:
        body = f"SQL error: {exc}"
    conn.close()
    return f"<html><body><form action='/search'>Search: <input name='q' value='{q}'><button>Go</button></form>{body}</body></html>"


@app.route("/comment", methods=["GET", "POST"])
def comment():
    text = request.values.get("text", "")
    # Intentionally vulnerable: unescaped reflection for demo purposes.
    return f"""
    <html><body>
    <form method="post" action="/comment">
      <input name="text" value="">
      <button>Post</button>
    </form>
    <div id="comment">{text}</div>
    </body></html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """
        <html><body>
        <form method="post" action="/login">
          Username: <input name="username"><br>
          Password: <input name="password" type="password"><br>
          <button>Login</button>
        </form>
        </body></html>
        """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=? AND password=?", (username, password))
    row = cur.fetchone()
    conn.close()
    if row:
        return "<html><body>Welcome! Login successful.</body></html>"
    return "<html><body>Invalid username or password.</body></html>", 401


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
