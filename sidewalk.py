import datetime
import hashlib
import os
import math

import sqlite3

from flask import Flask, request, render_template, g, redirect, session, send_file

from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, current_user, login_required

from flask_login.mixins import UserMixin

UPLOAD_FOLDER = "user_images"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app = Flask(__name__, static_folder="static", static_url_path="/static")
# 2MB max image size
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# Would be an environment variable in a production setup
app.secret_key = b'YOUR_SECRET_HERE'

bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "signup"


class User(UserMixin):
    def __init__(self, user_id, username, password):
        self.id = user_id
        self.username = username
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    return redirect("/login")


def get_db():
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = sqlite3.connect("sidewalk.db")

    return db


def get_activity_records():

    sql_query = """
        SELECT activity_records.id, users.username, step_count, duration, proof_filename
        FROM activity_records
        INNER JOIN users ON activity_records.user_id = users.id
        ORDER BY activity_records.id DESC
    """

    records = get_db().execute(sql_query).fetchall()

    return records


def generate_leaderboard():

    sql_query = """
        SELECT users.username, sum(activity_records.step_count), sum(activity_records.duration)
        FROM activity_records
        INNER JOIN users ON activity_records.user_id = users.id
        GROUP BY user_id
        ORDER BY sum(step_count) DESC
    """

    records = get_db().execute(sql_query).fetchall()

    return records


def localize_number(num):
    return f"{num:,}"


def convert_seconds(seconds):
    return datetime.timedelta(seconds=seconds)


def insert_activity(user_id, step_count, duration, file_hash):
    sql_query = """
        INSERT INTO activity_records (id, user_id, step_count, duration, proof_filename)
        VALUES (NULL, ?, ?, ?, ?);
    """

    db = get_db()

    db.execute(sql_query, (user_id, step_count, duration, file_hash))
    db.commit()


@app.route("/", methods=["GET"])
@login_required
def index():
    if current_user.is_authenticated:
        recent_activities = get_activity_records()
        leaderboard = generate_leaderboard()

        current_date = datetime.date.today()
        current_weekday = current_date.weekday()

        days_left = 7 - current_weekday

        avg_steps_to_overtake = 0

        for i, user in enumerate(leaderboard):
            if user[0] == current_user.username:
                if i > 0:
                    total_steps_needed = leaderboard[i - 1][1] - user[1]
                    avg_steps_to_overtake = math.ceil(total_steps_needed / days_left)
                else:
                    break

        return render_template(
            "index.html",
            recent_activities=recent_activities,
            leaderboard=leaderboard,
            convert_seconds=convert_seconds,
            localize_number=localize_number,
            days_left=days_left,
            avg_steps_to_overtake=avg_steps_to_overtake
        )

    return redirect("/login")


def allowed_file(filename):
    return "." in filename and \
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/submit_activity", methods=["GET", "POST"])
@login_required
def submit_activity():

    if request.method == "GET":
        if current_user.is_authenticated:
            return render_template("submit_activity.html")

        return redirect("/login")

    elif request.method == "POST":

        if not current_user.is_authenticated:
            return redirect("/login")

        errors = {
            "step_count": [],
            "duration": [],
            "proof_file": []
        }

        print(request.form)

        if "step_count" not in request.form:
            errors["step_count"].append("Invalid step count.")
            return render_template("submit_activity.html", errors=errors), 400
        elif "duration" not in request.form:
            errors["duration"].append("Invalid duration.")
            return render_template("submit_activity.html", errors=errors, step_count=request.form["step_count"]), 400
        elif "proof_file" not in request.files:
            print("file proof not in there")
            errors["proof_file"].append("Invalid proof file.")
            return render_template(
                "submit_activity.html",
                errors=errors,
                step_count=request.form["step_count"],
                duration=request.form["duration"]
            ), 400

        print(f"Submitting activity as {session}")

        step_count = request.form["step_count"]
        duration = request.form["duration"]

        try:
            step_count = int(step_count)
        except ValueError:
            errors["step_count"].append("Invalid step count.")
            return render_template("submit_activity.html", errors=errors), 400

        try:
            duration = int(duration)
        except ValueError:
            errors["duration"].append("Invalid duration.")
            return render_template("submit_activity.html", errors=errors, step_count=step_count), 400

        file = request.files["proof_file"]

        if not file or file.filename == '':
            print("No selected proof file")
            errors["proof_file"].append("Missing proof file.")
            return render_template("submit_activity.html", errors=errors, step_count=step_count, duration=duration), 400

        if allowed_file(file.filename):
            file_hash = hashlib.md5(file.read()).hexdigest()
            file.seek(0)
            file.save(os.path.join(UPLOAD_FOLDER, file_hash))

            insert_activity(session["user_id"], step_count, duration, file_hash)
        else:
            errors["proof_file"].append("Invalid proof file.")
            return render_template("submit_activity.html", errors=errors, step_count=step_count, duration=duration), 400

        print(request.form)
        print(request.files)

        return redirect("/")


def get_user_by_name(username: str):
    sql_query = """
        SELECT id, username, password
        FROM users
        WHERE username = ?
        LIMIT 1
    """

    record = get_db().execute(sql_query, (username, )).fetchone()

    if record:
        return User(record[0], record[1], record[2])
    else:
        return None


def get_user_by_id(user_id):
    sql_query = """
        SELECT id, username, password
        FROM users
        WHERE id = ?
        LIMIT 1
    """

    record = get_db().execute(sql_query, (user_id, )).fetchone()

    if record:
        return User(record[0], record[1], record[2])
    else:
        return None


def is_valid_access_code(code: str):
    sql_query = """
        SELECT 1
        FROM access_codes
        WHERE code = ? AND claimed_by IS NULL
        LIMIT 1
    """

    record = get_db().execute(sql_query, (code,)).fetchone()

    return record is not None


def claim_access_code(user_id: int, code: str):
    sql_query = """
        UPDATE access_codes
        SET claimed_by=?
        WHERE code=?;
    """

    db = get_db()

    db.execute(sql_query, (user_id, code))
    db.commit()


def register_user(username, plain_password, access_code):
    sql_query = """
        INSERT INTO users (id, username, password)
        VALUES (NULL, ?, ?);
    """

    password_hash = bcrypt.generate_password_hash(plain_password, 12)

    db = get_db()

    db.execute(sql_query, (username, password_hash))
    db.commit()


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect("/")

        return render_template("signup.html")
    elif request.method == "POST":

        errors = {
            "username": [],
            "password": [],
            "access_code": []
        }

        if "username" not in request.form:
            errors["username"].append("Invalid username.")
            return render_template("signup.html", errors=errors)
        elif "password" not in request.form:
            errors["password"].append("Invalid password.")
            return render_template("signup.html", errors=errors)
        elif "access_code" not in request.form:
            errors["username"].append("Invalid access code.")
            return render_template("signup.html", errors=errors)

        username = request.form["username"]
        username_len = len(username)

        password = request.form["password"]
        password_len = len(password)

        access_code = request.form["access_code"]

        if username_len < 3:
            errors["username"].append("The username must be at least 3 characters.")
        elif username_len > 16:
            errors["username"].append("The username can be at most 16 characters.")
        elif get_user_by_name(username) is not None:
            errors["username"].append("This username is already taken.")

        if password_len < 8:
            errors["password"].append("The password must be at least 8 characters.")
        elif password_len > 24:
            errors["password"].append("The password can be at most 24 characters.")

        if len(access_code) != 15 or not is_valid_access_code(access_code):
            errors["access_code"].append("Invalid access code.")

        if len(errors["username"]) or len(errors["password"]) or len(errors["access_code"]):
            print(f"Invalid signup attempt: {request.form}")
            return render_template("signup.html", errors=errors, username=username), 401

        # If all of the above checks pass, we should have a valid username, password, and access code

        register_user(username, password, access_code)

        sql_query = """
            SELECT id
            FROM users
            WHERE username = ?
            LIMIT 1
        """

        record = get_db().execute(sql_query, (username,)).fetchone()
        if record and len(record) == 1:
            claim_access_code(record[0], access_code)
        else:
            print("User was not added to database correctly.")

        print(request.form)

        return redirect("/", code=302)


def is_correct_login(username, plain_password):
    user = get_user_by_name(username)

    if user:
        return bcrypt.check_password_hash(user.password, plain_password)
    else:
        return False


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect("/")

        return render_template("login.html")
    elif request.method == "POST":

        def abort_as_invalid():
            print(f"Invalid login attempt: {request.form}")

            return render_template("login.html", invalid_login=True), 401

        if "username" not in request.form or "password" not in request.form:
            return abort_as_invalid()

        username = request.form["username"]
        username_len = len(username)

        password = request.form["password"]
        password_len = len(password)

        if username_len < 3 or username_len > 16:
            return abort_as_invalid()

        if password_len < 8 or password_len > 24:
            return abort_as_invalid()

        if not is_correct_login(username, password):
            return abort_as_invalid()

        user = get_user_by_name(username)

        # If all of the above checks pass, we should have a valid username and password
        login_user(user)

        session["username"] = user.username
        session["user_id"] = user.id

        return redirect("/")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def rand_str(chars, N):
    import random

    return "".join(random.choice(chars) for _ in range(N))


def create_new_access_code():
    import string

    conn = sqlite3.connect("sidewalk.db")

    sql_query = """
        INSERT INTO access_codes (id, code, claimed_by)
        VALUES (NULL, ?, NULL);
    """

    code = rand_str(string.ascii_letters + string.digits, 15)

    conn.execute(sql_query, (code,))
    conn.commit()


def get_image_from_activity(activity_id: int) -> str:
    sql_query = """
        SELECT proof_filename
        FROM activity_records
        WHERE id = ?
    """

    records = get_db().execute(sql_query, (activity_id,)).fetchone()

    if records is not None and records[0]:
        return records[0]
    else:
        return None


@app.route("/proof/<activity_id>")
@login_required
def proof(activity_id):
    image_file = get_image_from_activity(activity_id)

    if image_file:
        return send_file(f"user_images/{image_file}", mimetype="image")
    else:
        return redirect("/")


if __name__ == "__main__":

    # create_new_access_code()

    print(allowed_file("dsa.jpg"))

    # app.run(host="0.0.0.0")
