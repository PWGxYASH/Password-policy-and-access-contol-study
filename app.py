# app.py
from flask import Flask, render_template
from flask_migrate import Migrate
from ext import db  # shared instance

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)        # <-- bind db to this app
migrate = Migrate(app, db)

# Import models AFTER db.init_app
from models import User, PasswordResetOTP, AuditLog
from auth import auth_bp

app.register_blueprint(auth_bp)

@app.route('/')
def index():
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, port=5502)
