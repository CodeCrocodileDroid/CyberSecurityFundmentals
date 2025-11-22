import hashlib
import bcrypt
import secrets
import string


# Simple MD5 hashing (not recommended for passwords)
def md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


# Secure password hashing with bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


# Password strength checker
def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    if any(c in string.punctuation for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    strength = ["Very Weak", "Weak", "Fair", "Good", "Strong"][min(score, 4)]
    return strength, feedback


# Password generator
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# Example usage
password = "MySecret123!"
print(f"MD5 Hash: {md5_hash(password)}")
hashed = hash_password(password)
print(f"BCrypt Hash: {hashed}")
print(f"Password Verified: {verify_password(password, hashed)}")
print(f"Password Strength: {check_password_strength(password)}")
print(f"Generated Password: {generate_password()}")