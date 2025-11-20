from app import app
from models import db

# ----- Initialize Database -----
with app.app_context():
    # Drop all tables if needed (optional)
    # db.drop_all()

    # Create tables based on models
    db.create_all()
    print("Database created successfully. You can now register your first user!")
