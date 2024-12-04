import json
from server import app, db, User, CV  # Import your Flask app and models
from werkzeug.security import generate_password_hash
from sqlalchemy import text, inspect
from datetime import datetime

# Load the JSON data
with open('exported_data.json', 'r') as f:
    data = json.load(f)

with app.app_context():
    # Disable foreign key constraints
    db.session.execute(text('PRAGMA foreign_keys = OFF'))

    # Truncate tables
    db.session.execute(text('DELETE FROM cv'))
    db.session.execute(text('DELETE FROM user'))
    
    # Reset auto-increment counters if sqlite_sequence exists
    inspector = inspect(db.engine)
    if 'sqlite_sequence' in inspector.get_table_names():
        db.session.execute(text('DELETE FROM sqlite_sequence WHERE name="cv" OR name="user"'))
    
    db.session.commit()
    
    print("Tables truncated.")

    # Import users
    for user_data in data['users']:
        user = User(
            id=user_data[0],
            email=user_data[1],
            password_hash=user_data[2]
        )
        db.session.add(user)

    # Import CVs
    for cv_data in data['cvs']:
        # Convert the created_at string to a datetime object
        created_at = datetime.fromisoformat(cv_data[4].rstrip('Z'))
        cv = CV(
            id=cv_data[0],
            user_id=cv_data[1],
            data=json.loads(cv_data[2]),
            source_url=cv_data[3],
            created_at=created_at,
            name=cv_data[5]
        )
        db.session.add(cv)

    # Re-enable foreign key constraints
    db.session.execute(text('PRAGMA foreign_keys = ON'))

    # Commit all changes
    db.session.commit()

print("Data import completed!")
