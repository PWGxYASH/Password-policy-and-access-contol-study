# utils.py
import re

def password_policy(password):
    """
    Simple password policy:
    - min 8 chars
    - at least 1 uppercase
    - at least 1 lowercase
    - at least 1 digit
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    return True, "Password is valid."
