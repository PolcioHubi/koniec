import bcrypt
import secrets
import datetime
import sqlite3
import sys
import logging
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
from flask_login import UserMixin
from database import get_db_connection

class User(UserMixin):
    def __init__(self, id, username, is_active=True):
        self.id = id
        self.username = username
        self._is_active = is_active

    @property
    def is_active(self):
        return self._is_active

    def get_id(self):
        return str(self.id)

class UserAuthManager:
    def __init__(self, db_path: Optional[str] = None, conn: Optional[sqlite3.Connection] = None):
        """
        Inicjalizuje menedżera.
        """
        self.db_path = db_path
        self.conn = conn # Persistent connection for tests

    @contextmanager
    def _managed_connection(self):
        """
        Prywatny menedżer kontekstu do zarządzania połączeniem z bazą danych.
        Używa istniejącego połączenia (self.conn) jeśli dostępne, w przeciwnym razie tworzy nowe.
        """
        if self.conn:
            yield self.conn
        else:
            connection = get_db_connection(self.db_path)
            connection.row_factory = sqlite3.Row
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _hash_password(self, password: str) -> str:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        return hashed.decode('utf-8')

    def _check_password(self, hashed_password: str, password: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except (ValueError, TypeError):
            return False

    def validate_referral_code(self, code: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        """Checks if a referral code (username) exists and is active."""
        if conn: # Use the passed connection
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM users WHERE username = ? AND is_active = 1', (code,))
            user = cursor.fetchone()
        elif self.conn: # For testing purposes, if self.conn is set
            cursor = self.conn.cursor()
            cursor.execute('SELECT username FROM users WHERE username = ? AND is_active = 1', (code,))
            user = cursor.fetchone()
        else: # If no connection is passed and not in test mode, create a new managed connection
            with self._managed_connection() as managed_conn:
                cursor = managed_conn.cursor()
                cursor.execute('SELECT username FROM users WHERE username = ? AND is_active = 1', (code,))
                user = cursor.fetchone()
        return user is not None

    def generate_access_key(self, description: str = "", expires_days: int = 30) -> str:
        access_key = secrets.token_urlsafe(32)
        expires_at = None
        if expires_days > 0:
            expires_at = (datetime.datetime.now() + datetime.timedelta(days=expires_days)).isoformat()
        
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                'INSERT INTO access_keys (key, description, created_at, expires_at, is_active, used_count, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (access_key, description, datetime.datetime.now().isoformat(), expires_at, 1, 0, None)
            )
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO access_keys (key, description, created_at, expires_at, is_active, used_count, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (access_key, description, datetime.datetime.now().isoformat(), expires_at, 1, 0, None)
                )
        return access_key

    def validate_access_key(self, access_key: str, conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, str]:
        if conn: # Use the passed connection
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM access_keys WHERE key = ?', (access_key,))
            key_data = cursor.fetchone()
        elif self.conn: # For testing purposes, if self.conn is set
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM access_keys WHERE key = ?', (access_key,))
            key_data = cursor.fetchone()
        else: # If no connection is passed and not in test mode, create a new managed connection
            with self._managed_connection() as managed_conn:
                cursor = managed_conn.cursor()
                cursor.execute('SELECT * FROM access_keys WHERE key = ?', (access_key,))
                key_data = cursor.fetchone()

        if not key_data:
            return False, "Nieprawidłowy klucz dostępu"
        
        key_data = dict(key_data)

        if not key_data.get("is_active", 0):
            return False, "Klucz dostępu został dezaktywowany"
        if key_data.get("expires_at"):
            expires_at = datetime.datetime.fromisoformat(key_data["expires_at"])
            if datetime.datetime.now() > expires_at:
                return False, "Klucz dostępu wygasł"
        return True, ""

    def use_access_key(self, access_key: str):
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('UPDATE access_keys SET used_count = used_count + 1, last_used = ?, is_active = 0 WHERE key = ?', 
                           (datetime.datetime.now().isoformat(), access_key))
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE access_keys SET used_count = used_count + 1, last_used = ?, is_active = 0 WHERE key = ?', 
                               (datetime.datetime.now().isoformat(), access_key))

    def deactivate_access_key(self, access_key: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('UPDATE access_keys SET is_active = 0 WHERE key = ?', (access_key,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE access_keys SET is_active = 0 WHERE key = ?', (access_key,))
                rows_affected = cursor.rowcount
        return rows_affected > 0

    def get_access_keys(self) -> List[Dict]:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT * FROM access_keys ORDER BY created_at DESC')
            keys_data = cursor.fetchall()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM access_keys ORDER BY created_at DESC')
                keys_data = cursor.fetchall()
        return [dict(key) for key in keys_data]

    def register_user(self, username: str, password: str, access_key: str, referral_code: Optional[str] = None, conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, str, Optional[str]]:
        is_valid, error_msg = self.validate_access_key(access_key, conn=conn)
        if not is_valid:
            return False, error_msg, None
        
        if len(username) < 3:
            return False, "Nazwa użytkownika musi mieć co najmniej 3 znaki", None
        if len(password) < 6:
            return False, "Hasło musi mieć co najmniej 6 znaków", None

        result_success = False
        result_message = ""
        result_recovery_token = None

        with self._managed_connection() as db_conn:
            cursor = db_conn.cursor()
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            existing_user = cursor.fetchone()
            if existing_user:
                result_message = "Użytkownik o tej nazwie już istnieje"
            else:
                hashed_password = self._hash_password(password)
                recovery_token = secrets.token_urlsafe(16)
                cursor.execute(
                    'INSERT INTO users (username, password, created_at, is_active, last_login, access_key_used, hubert_coins, recovery_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (username, hashed_password, datetime.datetime.now().isoformat(), 1, None, access_key, 0, recovery_token)
                )
                cursor.execute('UPDATE access_keys SET used_count = used_count + 1, last_used = ?, is_active = 0 WHERE key = ?',
                               (datetime.datetime.now().isoformat(), access_key))
                
                if referral_code and self.validate_referral_code(referral_code, conn=db_conn):
                    cursor.execute('UPDATE users SET hubert_coins = hubert_coins + 1 WHERE username = ?', (referral_code,))
                    self.create_notification(username, "Witaj w mObywatel! Dziękujemy za rejestrację.", conn=db_conn)
                    result_success = True
                    result_message = "Użytkownik zarejestrowany pomyślnie. Otrzymałeś 1 Hubert Coin za polecenie!"
                    result_recovery_token = recovery_token
                else:
                    self.create_notification(username, "Witaj w mObywatel! Dziękujemy za rejestrację.", conn=db_conn)
                    result_success = True
                    result_message = "Użytkownik zarejestrowany pomyślnie"
                    result_recovery_token = recovery_token

        return result_success, result_message, result_recovery_token

    def authenticate_user(self, username: str, password: str, conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, str, Optional[User]]:
        with self._managed_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()

            if not user_data:
                return False, "Nieprawidłowa nazwa użytkownika lub hasło", None

            user_data = dict(user_data)

            if not user_data.get("is_active", 0):
                return False, "Konto użytkownika zostało dezaktywowane", None

            stored_password = user_data.get("password")
            if stored_password and self._check_password(stored_password, password):
                cursor.execute('UPDATE users SET last_login = ? WHERE username = ?', 
                               (datetime.datetime.now().isoformat(), username))
                user = User(id=user_data['username'], username=user_data['username'], is_active=user_data['is_active'])
                return True, "Logowanie pomyślne", user

            return False, "Nieprawidłowa nazwa użytkownika lub hasło", None

    def get_user_info(self, username: str, conn: Optional[sqlite3.Connection] = None) -> Optional[Dict]:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT username, created_at, is_active, last_login, access_key_used, hubert_coins FROM users WHERE username = ?', (username,))
            user_data = cursor.fetchone()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username, created_at, is_active, last_login, access_key_used, hubert_coins FROM users WHERE username = ?', (username,))
                user_data = cursor.fetchone()
        return dict(user_data) if user_data else None

    def get_user_by_id(self, user_id: str, conn: Optional[sqlite3.Connection] = None) -> Optional[User]:
        with self._managed_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT username, is_active FROM users WHERE username = ?', (user_id,))
            user_data = cursor.fetchone()
        if user_data:
            return User(id=user_data['username'], username=user_data['username'], is_active=user_data['is_active'])
        return None

    def get_all_users(self, include_passwords: bool = False, conn: Optional[sqlite3.Connection] = None) -> List[Dict]:
        if self.conn:
            cursor = self.conn.cursor()
            if include_passwords:
                cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
            else:
                cursor.execute('SELECT username, created_at, is_active, last_login, access_key_used, hubert_coins FROM users ORDER BY created_at DESC')
            users_data = cursor.fetchall()
            if users_data is None:
                return []
            return [dict(user) for user in users_data if user is not None]
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                if include_passwords:
                    cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
                else:
                    cursor.execute('SELECT username, created_at, is_active, last_login, access_key_used, hubert_coins FROM users ORDER BY created_at DESC')
                users_data = cursor.fetchall()
                if users_data is None:
                    return []
                return [dict(user) for user in users_data if user is not None]

    def deactivate_user(self, username: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('UPDATE users SET is_active = 0 WHERE username = ?', (username,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_active = 0 WHERE username = ?', (username,))
                rows_affected = cursor.rowcount
        return rows_affected > 0

    def activate_user(self, username: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('UPDATE users SET is_active = 1 WHERE username = ?', (username,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_active = 1 WHERE username = ?', (username,))
                rows_affected = cursor.rowcount
        return rows_affected > 0
            
    def toggle_user_status(self, username: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('UPDATE users SET is_active = NOT is_active WHERE username = ?', (username,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_active = NOT is_active WHERE username = ?', (username,))
                rows_affected = cursor.rowcount
        return rows_affected > 0

    def delete_access_key(self, access_key: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        """Delete an access key completely"""
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM access_keys WHERE key = ?', (access_key,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM access_keys WHERE key = ?', (access_key,))
                rows_affected = cursor.rowcount
        return rows_affected > 0

    def get_all_access_keys(self) -> List[Dict]:
        return self.get_access_keys()

    def delete_user(self, username: str, conn: Optional[sqlite3.Connection] = None) -> bool:
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM users WHERE username = ?', (username,))
            rows_affected = cursor.rowcount
            self.conn.commit()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE username = ?', (username,))
                rows_affected = cursor.rowcount
        return rows_affected > 0

    def update_hubert_coins(self, username: str, amount: int, conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, str]:
        """
        Aktualizuje ilość Hubert Coins dla użytkownika.
        Zwraca krotkę (bool, str) gdzie bool oznacza sukces operacji,
        a str zawiera komunikat o wyniku lub błędzie.
        """
        try:
            if self.conn:
                cursor = self.conn.cursor()
                cursor.execute('SELECT hubert_coins FROM users WHERE username = ?', (username,))
                result = cursor.fetchone()
                if not result:
                    return False, "Nie znaleziono użytkownika"
                current_coins = result['hubert_coins']
                new_balance = current_coins + amount
                if new_balance < 0:
                    return False, "Niewystarczająca ilość Hubert Coins"
                cursor.execute(
                    'UPDATE users SET hubert_coins = ? WHERE username = ?', 
                    (new_balance, username)
                )
                self.conn.commit()
                return True, f"Zaktualizowano saldo Hubert Coins do: {new_balance}"
            else:
                with self._managed_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT hubert_coins FROM users WHERE username = ?', (username,))
                    result = cursor.fetchone()
                    if not result:
                        return False, "Nie znaleziono użytkownika"
                    current_coins = result['hubert_coins']
                    new_balance = current_coins + amount
                    if new_balance < 0:
                        return False, "Niewystarczająca ilość Hubert Coins"
                    cursor.execute(
                        'UPDATE users SET hubert_coins = ? WHERE username = ?', 
                        (new_balance, username)
                    )
                    return True, f"Zaktualizowano saldo Hubert Coins do: {new_balance}"
        except sqlite3.Error as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Błąd bazy danych: {str(e)}"
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Wystąpił nieoczekiwany błąd: {str(e)}"

    def reset_user_password(self, username: str, new_password: str, conn: Optional[sqlite3.Connection] = None) -> Tuple[bool, str]:
        """
        Resetuje hasło użytkownika (przez admina).
        """
        if len(new_password) < 6:
            return False, "Hasło musi mieć co najmniej 6 znaków"
        hashed_password = self._hash_password(new_password)
        try:
            if self.conn:
                cursor = self.conn.cursor()
                cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
                if not cursor.fetchone():
                    return False, "Nie znaleziono użytkownika"
                cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
                self.conn.commit()
                return True, "Hasło zostało zresetowane"
            else:
                with self._managed_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
                    if not cursor.fetchone():
                        return False, "Nie znaleziono użytkownika"
                    cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
                    return True, "Hasło zostało zresetowane"
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            return False, f"Błąd resetowania hasła: {str(e)}"

    def get_stats(self, conn: Optional[sqlite3.Connection] = None) -> Dict:
        """
        Zwraca statystyki: liczba użytkowników, lista aktywnych, użytkownik z największą liczbą Hubert Coin.
        """
        if self.conn:
            cursor = self.conn.cursor()
            cursor.execute('SELECT username, is_active, hubert_coins FROM users')
            users_data = cursor.fetchall()
        else:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT username, is_active, hubert_coins FROM users')
                users_data = cursor.fetchall()
        users = [dict(u) for u in users_data]
        total_users = len(users)
        active_users = [u['username'] for u in users if u.get('is_active', 0)]
        top_user = max(users, key=lambda u: u.get('hubert_coins', 0), default=None)
        top_username = top_user['username'] if top_user else None
        top_coins = top_user['hubert_coins'] if top_user else 0
        return {
            'total_users': total_users,
            'active_users': active_users,
            'top_username': top_username,
            'top_coins': top_coins,
        }

    def create_notification(self, user_id: str, message: str, conn: Optional[sqlite3.Connection] = None):
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, ?)',
                (user_id, message, datetime.datetime.now().isoformat())
            )
        else:
            with self._managed_connection() as managed_conn:
                cursor = managed_conn.cursor()
                cursor.execute(
                    'INSERT INTO notifications (user_id, message, created_at) VALUES (?, ?, ?)',
                    (user_id, message, datetime.datetime.now().isoformat())
                )

    def get_notifications(self, user_id: str, conn: Optional[sqlite3.Connection] = None) -> List[Dict]:
        with self._managed_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
            notifications = cursor.fetchall()
        return [dict(notification) for notification in notifications]

    def mark_notification_as_read(self, notification_id: int, conn: Optional[sqlite3.Connection] = None):
        with self._managed_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notification_id,))

    def generate_password_reset_token(self, username: str) -> Optional[str]:
        """
        Generuje token resetowania hasła dla użytkownika i zapisuje go w bazie danych.
        Token jest ważny przez 1 godzinę.
        """
        token = secrets.token_urlsafe(32)
        expires_at = (datetime.datetime.now() + datetime.timedelta(hours=1)).isoformat()
        try:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE username = ?',
                    (token, expires_at, username)
                )
                if cursor.rowcount == 0:
                    return None # User not found
            return token
        except Exception as e:
            print(f"Error generating password reset token: {e}")
            return None

    def validate_password_reset_token(self, token: str) -> Optional[str]:
        """
        Waliduje token resetowania hasła. Zwraca nazwę użytkownika, jeśli token jest ważny, w przeciwnym razie None.
        """
        try:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT username, password_reset_expires FROM users WHERE password_reset_token = ?',
                    (token,)
                )
                user_data = cursor.fetchone()
                if not user_data:
                    return None # Token not found
                
                user_data = dict(user_data)
                expires_at = datetime.datetime.fromisoformat(user_data['password_reset_expires'])
                
                if datetime.datetime.now() > expires_at:
                    return None # Token expired
                
                return user_data['username']
        except Exception as e:
            print(f"Error validating password reset token: {e}")
            return None

    def reset_user_password_with_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        """
        Resetuje hasło użytkownika za pomocą tokena.
        """
        username = self.validate_password_reset_token(token)
        if not username:
            return False, "Nieprawidłowy lub wygasły token resetowania hasła"
        
        if len(new_password) < 6:
            return False, "Nowe hasło musi mieć co najmniej 6 znaków"
        
        hashed_password = self._hash_password(new_password)
        try:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE username = ?',
                    (hashed_password, username)
                )
            return True, "Hasło zostało pomyślnie zresetowane"
        except Exception as e:
            print(f"Error resetting password with token: {e}")
            return False, f"Wystąpił błąd podczas resetowania hasła: {str(e)}"

    def reset_password_with_recovery_token(self, username: str, recovery_token: str, new_password: str) -> Tuple[bool, str]:
        """
        Resetuje hasło użytkownika za pomocą tokena odzyskiwania.
        """
        try:
            with self._managed_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT username FROM users WHERE username = ? AND recovery_token = ?',
                    (username, recovery_token)
                )
                user_data = cursor.fetchone()
                if not user_data:
                    return False, "Nieprawidłowa nazwa użytkownika lub token odzyskiwania"
                
                if len(new_password) < 6:
                    return False, "Nowe hasło musi mieć co najmniej 6 znaków"
                
                hashed_password = self._hash_password(new_password)
                cursor.execute(
                    'UPDATE users SET password = ? WHERE username = ?',
                    (hashed_password, username)
                )
                return True, "Hasło zostało pomyślnie zresetowane za pomocą tokena odzyskiwania"
        except Exception as e:
            print(f"Error resetting password with recovery token: {e}")
            return False, f"Wystąpił błąd podczas resetowania hasła: {str(e)}"