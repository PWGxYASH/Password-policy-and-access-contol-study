from flask import Flask, render_template
from auth import auth_bp
from api import api_bp
from models import db
from flask_jwt_extended import JWTManager
from flask_mail import Mail
import os

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

app.secret_key = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"

# ---- Email Config (use a test Gmail account for demo) ----
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"       # Change this
app.config["MAIL_PASSWORD"] = "your_email_app_password"    # Use app password, not main password

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)
mail = Mail(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(api_bp, url_prefix="/api")

@app.route('/')
def index():
    return render_template('login.html')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
app.run(host='0.0.0.0', port=5000, debug=True)
