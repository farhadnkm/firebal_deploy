#!/usr/bin/env python3
"""
seed_user.py — Initialize database and create first admin user.
Run this once to set up auth.

Usage:
    python seed_user.py
    (prompts for username and password)
"""
import sys
from auth import init_db, create_user, get_user_by_username

def create_seed_user(username: str, password: str, quiet: bool = False) -> dict | None:
    """Create a user if missing; return user dict or None if already exists."""
    init_db()
    if get_user_by_username(username):
        if not quiet:
            print(f"User '{username}' already exists")
        return None
    user = create_user(username, password)
    if not quiet:
        print(f"✓ User created: {user}")
    return user

def main():
    print("=== Initializing database ===")
    init_db()
    print("✓ Database initialized")
    
    print("\n=== Create first admin user ===")
    username = input("Username: ").strip()
    if not username:
        print("Error: Username cannot be empty")
        sys.exit(1)
    
    password = input("Password: ").strip()
    if not password:
        print("Error: Password cannot be empty")
        sys.exit(1)
    
    try:
        user = create_user(username, password)
        print(f"✓ User created: {user}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
