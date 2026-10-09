"""Promote an existing user to admin (run on the server, never exposed over HTTP).
Usage: python scripts/create_admin.py <username>"""
import os
import sqlite3
import sys

if len(sys.argv) != 2:
    sys.exit("usage: python scripts/create_admin.py <username>")
conn = sqlite3.connect(os.getenv("DB_PATH", "secure.db"))
cur = conn.execute("UPDATE users SET role = 'admin' WHERE username = ?", (sys.argv[1],))
conn.commit()
print("promoted" if cur.rowcount else "user not found")
