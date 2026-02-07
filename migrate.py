#!/usr/bin/env python
"""
Database migration script for WA Charters CRM security update.

This script adds:
- 'role' column to the User table
- 'AuditLog' table for tracking user actions

Run this script after updating the application to add the new security features.

Usage:
    python migrate.py
"""

import os
import sys
from datetime import datetime

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, AuditLog


def migrate():
    """Run database migrations."""
    with app.app_context():
        print("Starting database migration...")

        # Check if we're using SQLite or PostgreSQL
        db_url = app.config['SQLALCHEMY_DATABASE_URI']
        is_sqlite = 'sqlite' in db_url.lower()

        # Get the database engine
        engine = db.engine
        inspector = db.inspect(engine)

        # Check if User table exists
        if 'user' not in inspector.get_table_names():
            print("User table doesn't exist. Creating all tables...")
            db.create_all()
            print("All tables created successfully!")
            return

        # Check if 'role' column exists in User table
        user_columns = [col['name'] for col in inspector.get_columns('user')]

        if 'role' not in user_columns:
            print("Adding 'role' column to User table...")
            if is_sqlite:
                # SQLite requires a different approach
                db.session.execute(db.text(
                    "ALTER TABLE user ADD COLUMN role VARCHAR(20) DEFAULT 'viewer' NOT NULL"
                ))
            else:
                # PostgreSQL
                db.session.execute(db.text(
                    "ALTER TABLE \"user\" ADD COLUMN role VARCHAR(20) DEFAULT 'viewer' NOT NULL"
                ))
            db.session.commit()
            print("  'role' column added successfully!")

            # Set the first user as admin if there are existing users
            first_user = User.query.order_by(User.id).first()
            if first_user:
                print(f"  Setting {first_user.email} as admin...")
                first_user.role = User.ROLE_ADMIN
                db.session.commit()
                print(f"  {first_user.email} is now an admin!")
        else:
            print("  'role' column already exists.")

        # Check if AuditLog table exists
        if 'audit_log' not in inspector.get_table_names():
            print("Creating AuditLog table...")
            # Create only the AuditLog table
            AuditLog.__table__.create(engine, checkfirst=True)
            print("  AuditLog table created successfully!")
        else:
            print("  AuditLog table already exists.")

        print("\nMigration completed successfully!")
        print("\nSummary of changes:")
        print("  - User.role column: exists")
        print("  - AuditLog table: exists")

        # Show current users and their roles
        users = User.query.all()
        if users:
            print("\nCurrent users:")
            for user in users:
                print(f"  - {user.email}: {user.role}")
        else:
            print("\nNo users in database yet.")


if __name__ == '__main__':
    migrate()
