# admin.py
from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from models import User, AuditLog, db
from functools import wraps
from auth import login_required  # use your existing login_required
from decorators import login_required, role_required
admin_bp = Blueprint('admin', __name__, url_prefix='/admin', template_folder='templates/admin')

# --- Admin role decorator ---
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in first.', 'warning')
            return redirect(url_for('auth.login'))
        user = User.query.get(user_id)
        if not user or user.role != 'admin':
            flash('Access denied.', 'danger')
            return redirect(url_for('auth.dashboard'))
        return func(*args, **kwargs)
    return wrapper

# --- Admin Dashboard: Users ---
@admin_bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.all()
    return render_template('users.html', users=users)

@admin_bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"{user.username} deleted successfully.", "success")
    return redirect(url_for('admin.users'))

@admin_bp.route('/audit_logs')
@login_required
@admin_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)


@admin_bp.route('/dashboard')
@login_required
@role_required('admin')
def dashboard():
    users = User.query.all()
    return render_template('users.html', users=users)