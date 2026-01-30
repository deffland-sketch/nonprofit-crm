"""
Non-Profit CRM Startup Script

Usage:
    python run.py          - Initialize database and run the server
    python run.py --init   - Just initialize the database
"""

import sys
from app import app, db

def init_database():
    """Create all database tables."""
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")

if __name__ == '__main__':
    if '--init' in sys.argv:
        init_database()
    else:
        init_database()
        print("\nStarting Non-Profit CRM...")
        print("Open http://127.0.0.1:5000 in your browser")
        print("Press Ctrl+C to stop the server\n")
        app.run(debug=True, host='127.0.0.1', port=5000)
