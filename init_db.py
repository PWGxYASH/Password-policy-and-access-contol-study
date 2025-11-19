from app import app, db

# Create app context and initialize database
with app.app_context():
    db.create_all()
    print("Database recreated successfully with new schema!")
