import bcrypt
import sqlite3
import os
from typing import Optional


class Authentication:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
        self._initialize_database()

    def _initialize_database(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def login(self, email: str, password: str) -> bool:
        stored_hash = self.get_pass_from_db(email)
        if stored_hash is None:
            return False
        return self.verify_password(password, stored_hash)

    def register(self, email: str, password: str) -> bool:
        if self.get_pass_from_db(email) is not None:
            return False

        password_hash = self.hashed_password(password)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, password_hash)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def hashed_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')

    def verify_password(self, password: str, original_password: str) -> bool:
        return bcrypt.checkpw(
            password.encode('utf-8'),
            original_password.encode('utf-8')
        )

    def get_pass_from_db(self, email: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password_hash FROM users WHERE email = ?",
                (email,)
            )
            result = cursor.fetchone()
            return result[0] if result else None