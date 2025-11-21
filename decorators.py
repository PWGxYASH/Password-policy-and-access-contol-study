from functools import wraps
from flask import session, redirect, url_for, flash
from models import User

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        return func(*args, **kwargs)
    return wrapper

def role_required(role):
    """Protect a route so only users with a specific role can access it"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                flash('Please log in first.', 'warning')
                return redirect(url_for('auth.login'))
            user = User.query.get(user_id)
            if user.role != role:
                flash('Access denied: Insufficient privileges.', 'danger')
                return redirect(url_for('auth.dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator
