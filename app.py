from flask import Flask, render_template
from flask_migrate import Migrate
from ext import db
from models import User, PasswordResetOTP, AuditLog, add_missing_columns
from admin import admin_bp
from auth import auth_bp
def create_app():
    app = Flask(__name__)

    # --- Flask Config ---
    app.config['SECRET_KEY'] = 'super-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- Initialize Extensions ---
    db.init_app(app)
    Migrate(app, db)

    # --- Blueprints ---
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    

    # --- Database Init + Column Patching ---
    with app.app_context():
        db.create_all()          # create missing tables
        add_missing_columns()    # patch missing columns (like last_login)

    # --- Routes ---
    @app.route('/')
    def index():
        return render_template('register.html')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5503)
