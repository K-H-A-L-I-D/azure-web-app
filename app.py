from flask import Flask, render_template, make_response, redirect
from flask_restful import Api, request, Resource
from flask_bcrypt import Bcrypt
from datetime import datetime
from dotenv import load_dotenv
import pyodbc
import time
import os
import hmac
import hashlib

MAX_USERNAME_LENGTH = 20
MIN_PASSWORD_LENGTH = 8
APP_SECRET = "d7b7bf43487e4b93cdf8cb1914a16f58d9871f539a18cede391c543a1d26a713"
SESSION_EXPIRY_SECONDS = 60 * 60 * 24 * 7
BAD_LOGIN_MESSAGE = "Invalid username or password"

# Load environment variables if running locally
if "WEBSITE_HOSTNAME" not in os.environ:
    load_dotenv()

# Ensure database connection string is set
if "AZURE_SQL_CONNECTIONSTRING" not in os.environ:
    raise RuntimeError("AZURE_SQL_CONNECTIONSTRING is not set in environment variables.")

CONNECTION_STRING = os.environ["AZURE_SQL_CONNECTIONSTRING"]

app = Flask(__name__)
flask_bcrypt = Bcrypt(app)
api = Api(app)

def sign_session_cookie(session_id: str) -> str:
    """Sign the session ID with the app secret"""
    signature = hmac.new(
        APP_SECRET.encode(), session_id.encode(), hashlib.sha256
    ).hexdigest()
    return f"{session_id}:{signature}"

def verify_session_cookie_signature(cookie: str) -> str | None:
    """Verify the session cookie signature and return the session ID if valid"""
    try:
        session_id, signature = cookie.split(":")
        expected_signature = hmac.new(
            APP_SECRET.encode(), session_id.encode(), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(signature, expected_signature):
            return session_id
    except (ValueError, AttributeError):
        pass
    return None

def delete_session(session_id: str, cursor: pyodbc.Cursor) -> bool:
    """Delete the session from the database, returning True if successful."""
    try:
        cursor.execute("DELETE FROM Sessions WHERE sessionid = ?", (session_id,))
    except pyodbc.Error:
        return False
    return True
        
def get_user_from_session(session_cookie):
    """Get user information from a session cookie"""
    if not session_cookie:
        return None
        
    session_id = verify_session_cookie_signature(session_cookie)
    if session_id is None:
        return None
        
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            user = cursor.execute("""
                SELECT u.* FROM Users u
                JOIN Sessions s ON u.userid = s.userid
                WHERE s.sessionid = ? AND s.expiry > GETDATE()
            """, (session_id,)).fetchone()
            return user
        except pyodbc.Error:
            return None
        
def addResource(route: str):
    """Adds a resource to the API at the specified route"""
    def wrapper(cls, *args, **kwargs):
        api.add_resource(cls, route, *args, **kwargs)
        return cls
    return wrapper


# Database connection setup
def get_db_connection():
    """Creates a new database connection with retry logic"""
    max_attempts = 3
    retry_delay = 2  # seconds
    
    for attempt in range(1, max_attempts + 1):
        try:
            connection = pyodbc.connect(CONNECTION_STRING)
            if attempt > 1:
                print(f"Successfully connected to database on attempt {attempt}")
            return connection
        except pyodbc.Error as e:
            if attempt == max_attempts:
                # If we've reached max attempts, re-raise the exception
                print(f"Failed to connect to database after {max_attempts} attempts. Error: {str(e)}")
                raise
            
            # Log the failure and wait before retrying
            print(f"Database connection attempt {attempt} failed: {str(e)}")
            print(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)


@app.route("/")
def index():
    return render_template("index.html", name="Flask Bootstrap5")


def validate_username(username: str, db_cursor: pyodbc.Cursor) -> tuple[bool, str]:
    """Validates username"""
    if not username.isalnum():
        return False, "Username must be alphanumeric"
    elif len(username) > MAX_USERNAME_LENGTH:
        return False, "Username must be at most 20 characters long"
    elif db_cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
        return False, "Username already exists"
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """Validates password"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    return True, ""


@app.route("/signin")
def signin():
    return render_template("signin.html")


@addResource("/register")
class Register(Resource):
    def post(self):
        data = request.get_json()

        for key in ["username", "password", "displayName"]:
            if key not in data:
                return {"message": f"Missing required field: {key}"}, 400

        username = data.get("username")
        password = data.get("password")
        display_name = data.get("displayName")

        print("Receiving request: ", data)

        # Validate password
        success, message = validate_password(password)
        if not success:
            return {"message": message}, 400

        if not display_name:
            return {"message": "Display name cannot be empty"}, 400

        # Database connection
        with get_db_connection() as conn:
            cursor = conn.cursor()
            print("Connected to database!")

            # Validate username
            success, message = validate_username(username, cursor)
            if not success:
                return {"message": message}, 400

            # Hash password
            hashed_password = flask_bcrypt.generate_password_hash(password).decode("utf-8")

            try:
                cursor.execute(
                    "INSERT INTO Users (username, password, display_name) VALUES (?, ?, ?)",
                    (username, hashed_password, display_name),
                )
                cursor.commit()
            except pyodbc.Error:
                return {"message": "An error occurred while creating the user"}, 500
            finally:
                cursor.close()

            return {"message": "User created successfully"}, 201


def update_login_time(cursor, username):
    try:
        cursor.execute(
            "UPDATE Users SET last_login = ? WHERE username = ?",
            (datetime.now(), username),
        )
    except pyodbc.Error:
        return False
    return True

def create_session(username: str, cursor: pyodbc.Cursor) -> str:
    """Create a new session for the user and return the session ID"""
    session_id = cursor.execute(
        """INSERT INTO Sessions (sessionid, userid, expiry)
                    OUTPUT INSERTED.sessionid
                    VALUES (
                        NEWID(), 
                        (SELECT userid FROM Users WHERE username = ?),
                        DATEADD(WEEK, 1, GETDATE())
                    );""",
        (username,),
    ).fetchone()
    return session_id[0]

@addResource("/login")
class Login(Resource):
    def post(self):
        # login information may be sent in body or header.
        # let's assume that it is sent for body in the login endpoint.
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        # Check if the username and password match.
        with get_db_connection() as conn:
            # A cursor grabs is an object that allows you to interact with the database.
            cursor = conn.cursor()

            try:
                user = cursor.execute(
                    "SELECT * FROM Users WHERE username = ?", (username,)
                ).fetchone()
            except pyodbc.Error:
                return {"message": "An internal error has occured"}, 500

            # `user is None` checks if the user exists.
            # check_password_hash checks to see if the passwords match
            if user is None or not flask_bcrypt.check_password_hash(
                user.password, password
            ):
                return {"message": BAD_LOGIN_MESSAGE}, 400

            # Update the last login time
            update_login_time(conn, username)

            # get a session id
            session_id = create_session(username, cursor)
            # sign the session id
            session_cookie = sign_session_cookie(session_id)

            cursor.commit()
            cursor.close()

            response = make_response(
                {
                    "displayName": user.display_name,
                    "lastLogin": (user.last_login or user.create_date).isoformat(),
                },
                200,
            )
            response.set_cookie(
                "sessionID",
                samesite="Strict",
                value=session_cookie,
                max_age=SESSION_EXPIRY_SECONDS,
            )

            return response

@addResource("/logout")
class Logout(Resource):
    def post(self):
        # Get the session cookie from the request.
        # Note that cookies are sent automatically, so we don't have to change anything in the javascript code.
        session_cookie = request.cookies.get("sessionID")
        # If the sessionID doesn't exist in the header, then that means the cookie isn't set.
        # In that case, we should inform the user that they aren't logged in.
        if not session_cookie:
            return {"message": "Not logged in"}, 400
        # If it is set, then verify the session cookie signature. This will ensure that the
        # cookie they sent matches a cookie we sent them, and will resolve to the session id portion.
        session_id = verify_session_cookie_signature(session_cookie)
        # the verify_session_cookie_signature method returns None if verification wasn't successful.
        if session_id is None:
            return {"message": "Invalid session"}, 400


        # Now, we delete the session from the database.
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if session_id is not None:
                delete_session(session_id, cursor)
            cursor.commit()
            cursor.close()

        response = make_response({"message": "Successfully logged out."}, 200)
        # Delete the cookie. Easiest way to do this is to set an empty cookie, and set the expiry
        # to some point in the past.
        response.set_cookie("sessionID", value="", expires=0, samesite="Strict")
        return response

@addResource("/auth")
class AuthEndpoint(Resource):
    def get(self):
        user = get_user_from_session(request.cookies.get("sessionID"))
        if user is None:
            return {"message": "Not authenticated"}, 401

        return make_response(
            render_template("authorization.html", name=user.display_name)
        )

# Ensure Azure uses port 8000
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
