from app import app
from models import db,User

# ----- Initialize Database -----
with app.app_context():
    # Drop all tables if needed (optional)
    # db.drop_all()

    # Create tables based on models
    db.create_all()
    print("Database created successfully. You can now register your first user!")

admin = User(username='admin', phone_number='+911234567890', role='admin')
admin.set_password('Admin@1234')  # strong password
db.session.add(admin)
db.session.commit()