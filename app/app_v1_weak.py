from flask import Flask, request, render_template_string, redirect
import sqlite3, hashlib

app = Flask(__name__)
DB = "users.db"

LOGIN_FORM = """
<h2>Login</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
"""
REGISTER_FORM = """
<h2>Register</h2>
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Register</button>
</form>
"""

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # INTENTIONALLY WEAK — unsalted MD5. This is the vulnerability for Milestone 1.
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                         (username, pw_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken", 400
        finally:
            conn.close()
        return redirect("/login")
    return render_template_string(REGISTER_FORM)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        pw_hash = hashlib.md5(password.encode()).hexdigest()
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and user["password_hash"] == pw_hash:
            return "Login successful! Welcome " + username
        return "incorrect username or password", 401   # Hydra will match this failure string
    return render_template_string(LOGIN_FORM)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

