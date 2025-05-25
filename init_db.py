#!/usr/bin/env python3
"""Initialize the database for Heroku deployment."""

from app import create_app
from app.db import init_db

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        init_db()
        print("Database initialized successfully!")
