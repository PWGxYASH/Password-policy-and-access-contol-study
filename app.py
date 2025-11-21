from flask import Flask, render_template
from flask_migrate import Migrate
from ext import db
from models import User, PasswordResetOTP, AuditLog, add_missing_columns
from auth import auth_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

app.register_blueprint(auth_bp)

with app.app_context():
    db.create_all()
    add_missing_columns()  # <-- ensure last_login exists

@app.route('/')
def index():
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, port=5502)
