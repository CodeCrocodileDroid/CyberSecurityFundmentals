import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta


class SecureAuthSystem:
    def __init__(self):
        self.users = {}
        self.failed_attempts = {}
        self.session_tokens = {}

    def register_user(self, username, password):
        """Register new user with secure password storage"""
        if username in self.users:
            return False, "User already exists"

        # Hash password with salt
        salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac('sha256',
                                            password.encode('utf-8'),
                                            salt.encode('utf-8'),
                                            100000)

        self.users[username] = {
            'password_hash': password_hash.hex(),
            'salt': salt,
            'created_at': datetime.now()
        }

        return True, "User registered successfully"

    def authenticate_user(self, username, password):
        """Authenticate user with rate limiting"""
        # Rate limiting
        if self.is_rate_limited(username):
            return False, "Too many failed attempts. Try again later."

        if username not in self.users:
            self.log_failed_attempt(username)
            return False, "Invalid credentials"

        user = self.users[username]
        password_hash = hashlib.pbkdf2_hmac('sha256',
                                            password.encode('utf-8'),
                                            user['salt'].encode('utf-8'),
                                            100000)

        if password_hash.hex() == user['password_hash']:
            # Reset failed attempts on successful login
            if username in self.failed_attempts:
                del self.failed_attempts[username]

            # Generate session token
            token = self.generate_session_token(username)
            return True, f"Login successful. Session token: {token}"
        else:
            self.log_failed_attempt(username)
            return False, "Invalid credentials"

    def is_rate_limited(self, username):
        """Check if user is rate limited"""
        if username not in self.failed_attempts:
            return False

        attempts, last_attempt = self.failed_attempts[username]
        time_diff = datetime.now() - last_attempt

        # Lock account for 30 minutes after 5 failed attempts
        if attempts >= 5 and time_diff < timedelta(minutes=30):
            return True

        return False

    def log_failed_attempt(self, username):
        """Log failed authentication attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = [1, datetime.now()]
        else:
            self.failed_attempts[username][0] += 1
            self.failed_attempts[username][1] = datetime.now()

    def generate_session_token(self, username):
        """Generate secure session token"""
        token = secrets.token_urlsafe(32)
        self.session_tokens[token] = {
            'username': username,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24)
        }
        return token

    def validate_session(self, token):
        """Validate session token"""
        if token not in self.session_tokens:
            return False, "Invalid session"

        session = self.session_tokens[token]
        if datetime.now() > session['expires_at']:
            del self.session_tokens[token]
            return False, "Session expired"

        return True, session['username']


# Example usage
auth_system = SecureAuthSystem()

# Register users
success, message = auth_system.register_user("alice", "SecurePass123!")
print(f"Registration: {message}")

success, message = auth_system.register_user("bob", "AnotherSecurePass456@")
print(f"Registration: {message}")

# Authenticate users
success, message = auth_system.authenticate_user("alice", "SecurePass123!")
print(f"Authentication: {message}")

success, message = auth_system.authenticate_user("alice", "wrongpassword")
print(f"Authentication: {message}")

# Test session validation
token = message.split(": ")[-1] if "Session token:" in message else None
if token:
    valid, user = auth_system.validate_session(token)
    print(f"Session validation: {valid}, User: {user}")