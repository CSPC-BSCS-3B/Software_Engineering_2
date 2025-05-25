import functools
import re
import time
import logging
from datetime import datetime, timedelta
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    make_response,
    current_app
)
from werkzeug.security import check_password_hash, generate_password_hash
from markupsafe import escape
from app.db import get_db

# Configure logging for security auditing
logging.basicConfig(
    filename='security_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Rate limiting storage (in production, use Redis or database)
registration_attempts = {}
login_attempts = {}

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Rate limiting configuration
MAX_REGISTRATION_ATTEMPTS = 3
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 900  # 15 minutes

def check_rate_limit(ip_address, attempt_type):
    """Check if IP has exceeded rate limits"""
    current_time = time.time()
    attempts_dict = registration_attempts if attempt_type == 'registration' else login_attempts
    max_attempts = MAX_REGISTRATION_ATTEMPTS if attempt_type == 'registration' else MAX_LOGIN_ATTEMPTS
    
    if ip_address not in attempts_dict:
        attempts_dict[ip_address] = []
    
    # Remove old attempts outside the window
    attempts_dict[ip_address] = [
        attempt_time for attempt_time in attempts_dict[ip_address]
        if current_time - attempt_time < RATE_LIMIT_WINDOW
    ]
    
    return len(attempts_dict[ip_address]) < max_attempts

def record_attempt(ip_address, attempt_type):
    """Record an attempt for rate limiting"""
    current_time = time.time()
    attempts_dict = registration_attempts if attempt_type == 'registration' else login_attempts
    
    if ip_address not in attempts_dict:
        attempts_dict[ip_address] = []
    
    attempts_dict[ip_address].append(current_time)

def validate_username(username):
    """Validate username format and characters"""
    if not username:
        return "Error! Username field cannot be empty."
    
    # Username should be 3-30 characters, alphanumeric and underscores allowed
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return "Error! Username must be 3-30 characters long and contain only letters, numbers, and underscores."
    
    return None

def validate_password(password):
    """Validate password strength"""
    if not password:
        return "Error! Password field cannot be empty."
    
    # Minimum 8 characters
    if len(password) < 8:
        return "Error! Password must be at least 8 characters long."
    
    # Must contain at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return "Error! Password must contain at least one uppercase letter."
    
    # Must contain at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return "Error! Password must contain at least one lowercase letter."
    
    # Must contain at least one digit
    if not re.search(r'\d', password):
        return "Error! Password must contain at least one number."
    
    # Must contain at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Error! Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
    
    return None

def sanitize_input(input_string):
    """Sanitize input to prevent XSS attacks"""
    if input_string:
        return escape(input_string.strip())
    return input_string

def log_security_event(event_type, username=None, ip_address=None, success=False, details=None):
    """Log security events for auditing"""
    log_message = f"{event_type} - IP: {ip_address} - Username: {username} - Success: {success}"
    if details:
        log_message += f" - Details: {details}"
    
    if success:
        logging.info(log_message)
    else:
        logging.warning(log_message)

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
    else:
        g.user = (
            get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        )

# Ensure only logged-in users can access protected routes
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))  # Redirect to login if not authenticated
        return view(**kwargs)

    return wrapped_view  # Removed incorrect header modification

@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        # Get client IP for rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        
        # Check rate limiting
        if not check_rate_limit(client_ip, 'registration'):
            error = "Error! Too many registration attempts. Please try again later."
            log_security_event("REGISTRATION_RATE_LIMIT_EXCEEDED", ip_address=client_ip)
            flash(error)
            rap = "right-panel-active"
            return render_template("auth/auth.html", rap=rap, signup=True)
        
        # Record this attempt
        record_attempt(client_ip, 'registration')
        
        # Sanitize all inputs to prevent XSS
        username = sanitize_input(request.form.get("username"))
        first_name = sanitize_input(request.form.get("first_name"))
        middle_name = sanitize_input(request.form.get("middle_name"))
        no_middle_name = "no_middle_name" in request.form
        last_name = sanitize_input(request.form.get("last_name"))
        email = sanitize_input(request.form.get("email"))
        password = request.form.get("password")  # Don't sanitize password as it may contain special chars
        confirm_password = request.form.get("confirm_password")
        
        db = get_db()
        error = None
        
        # Comprehensive validation
        username_error = validate_username(username)
        if username_error:
            error = username_error
        elif not first_name:
            error = "Error! First Name field cannot be empty."
        elif no_middle_name == False and not middle_name:
            error = "Error! Middle Name field cannot be empty."
        elif no_middle_name and middle_name:
            error = "Error! I thought you have no middle name?"
        elif not last_name:
            error = "Error! Last Name field cannot be empty."
        elif not email:
            error = "Error! Email field cannot be empty."
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            error = "Error! Please enter a valid email address."
        else:
            password_error = validate_password(password)
            if password_error:
                error = password_error
            elif not confirm_password:
                error = "Error! Confirm Password field cannot be empty."
            elif password != confirm_password:
                error = "Error! Passwords do not match."
        
        # Check for duplicate username and email
        if error is None:
            existing_user = db.execute(
                "SELECT username FROM users WHERE username = ? OR email = ?", 
                (username, email)
            ).fetchone()
            
            if existing_user:
                if existing_user["username"] == username:
                    error = f"Error! Username '{username}' is already registered."
                else:
                    error = "Error! Email address is already registered."
                
                log_security_event("REGISTRATION_DUPLICATE_ATTEMPT", username=username, ip_address=client_ip, details=error)
        
        if error is None:
            try:
                start_time = time.time()
                
                # Use transaction for data consistency
                db.execute("BEGIN TRANSACTION")
                
                # Insert name record
                db.execute(
                    "INSERT INTO names (first_name, middle_name, no_middle_name, last_name) VALUES (?, ?, ?, ?)",
                    (first_name, middle_name, no_middle_name, last_name),
                )
                name_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                
                # Insert user record with hashed password
                db.execute(
                    "INSERT INTO users (name_id, username, password, email) VALUES (?, ?, ?, ?)",
                    (name_id, username, generate_password_hash(password), email),
                )
                user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                
                # Create default accounts: Wallet, Savings, Checking, Credit, Debit
                default_accounts = [
                    ("Wallet", "Debit", 1000.0),    # Starting balance for wallet
                    ("Savings", "Debit", 0.0),      # Savings account
                    ("Checking", "Debit", 0.0),     # Checking account
                    ("Credit Card", "Credit", 0.0), # Credit account
                    ("Cash", "Debit", 0.0)          # Cash account
                ]
                
                for account_name, account_type, balance in default_accounts:
                    db.execute(
                        "INSERT INTO accounts (user_id, account_name, account_type, balance) VALUES (?, ?, ?, ?)",
                        (user_id, account_name, account_type, balance)
                    )
                
                db.commit()
                
                end_time = time.time()
                registration_time = end_time - start_time
                
                # Log successful registration
                log_security_event("REGISTRATION_SUCCESS", username=username, ip_address=client_ip, success=True, 
                                 details=f"Registration completed in {registration_time:.2f} seconds")
                
                # Check if registration completed within acceptable time frame
                if registration_time > 2.0:
                    logging.warning(f"Registration for {username} took {registration_time:.2f} seconds (exceeds 2 second target)")
                
                flash("Account created successfully! Please sign in with your new credentials.", "success")
                return render_template("auth/auth.html", rap=None, login=True)
                
            except db.IntegrityError as e:
                db.rollback()
                error = f"Error! Registration failed due to data conflict. Please try again."
                log_security_event("REGISTRATION_DB_ERROR", username=username, ip_address=client_ip, details=str(e))
            except Exception as e:
                db.rollback()
                error = "Error! Registration failed. Please try again."
                log_security_event("REGISTRATION_GENERAL_ERROR", username=username, ip_address=client_ip, details=str(e))
        
        # Log failed registration attempt
        if error:
            log_security_event("REGISTRATION_FAILED", username=username, ip_address=client_ip, details=error)
        
        flash(error)

    rap = "right-panel-active"
    return render_template("auth/auth.html", rap=rap, signup=True)

@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        # Get client IP for rate limiting
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        
        # Check rate limiting
        if not check_rate_limit(client_ip, 'login'):
            error = "Error! Too many login attempts. Please try again later."
            log_security_event("LOGIN_RATE_LIMIT_EXCEEDED", ip_address=client_ip)
            flash(error)
            return render_template("auth/auth.html", rap=None, login=True)
        
        # Record this attempt
        record_attempt(client_ip, 'login')
        
        # Sanitize inputs
        username = sanitize_input(request.form.get("username"))
        password = request.form.get("password")
        
        db = get_db()
        error = None
        
        # Validate inputs
        if not username:
            error = "Error! Username field cannot be empty."
        elif not password:
            error = "Error! Password field cannot be empty."
        
        user = None
        if error is None:
            # Use parameterized query to prevent SQL injection
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

            if user is None:
                error = "Error! Incorrect username."
                log_security_event("LOGIN_INVALID_USERNAME", username=username, ip_address=client_ip)
            elif not check_password_hash(user["password"], password):
                error = "Error! Incorrect password."
                log_security_event("LOGIN_INVALID_PASSWORD", username=username, ip_address=client_ip)

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            log_security_event("LOGIN_SUCCESS", username=username, ip_address=client_ip, success=True)
            return redirect(url_for("dashboard.index"))

        flash(error)

    return render_template("auth/auth.html", rap=None, login=True)

@bp.route("/logout")
def logout():
    session.clear()
    response = make_response(redirect(url_for("index")))  # Create response object
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response  # Return response with cache control headers
