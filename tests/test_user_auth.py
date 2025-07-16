import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import datetime

from user_auth import UserAuthManager
from database import get_db_connection, init_db

@pytest.fixture(scope="function")
def auth_manager():
    # Setup: Create a clean test database before each test
    test_db_dir = os.path.join(os.path.dirname(__file__), 'temp_test_db')
    os.makedirs(test_db_dir, exist_ok=True)
    test_db_path = os.path.join(test_db_dir, 'test_database.db')
    
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    init_db(db_path=test_db_path)

    conn = get_db_connection(test_db_path)
    manager = UserAuthManager(db_path=test_db_path, conn=conn)
    yield manager

    # Teardown: Clean up the test database after each test
    conn.close()
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    if os.path.exists(test_db_dir):
        os.rmdir(test_db_dir)



def test_register_user_success(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    success, message, recovery_token = auth_manager.register_user("testuser", "password123", access_key)
    assert success is True
    assert "Użytkownik zarejestrowany pomyślnie" in message
    users = auth_manager.get_all_users(include_passwords=True)
    assert any(u["username"] == "testuser" for u in users)
    testuser_data = next(u for u in users if u["username"] == "testuser")
    assert auth_manager._check_password(testuser_data["password"], "password123")
    
    # Check if access key is deactivated after use
    keys = auth_manager.get_access_keys()
    assert next(k for k in keys if k["key"] == access_key)["is_active"] == 0

def test_register_user_duplicate(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("testuser", "password123", access_key)
    
    access_key_2 = auth_manager.generate_access_key("test_key_2") # Need a new key for a new attempt
    success, message, _ = auth_manager.register_user("testuser", "anotherpassword", access_key_2)
    assert success is False
    assert "Użytkownik o tej nazwie już istnieje" in message

def test_register_user_invalid_access_key(auth_manager):
    success, message, _ = auth_manager.register_user("testuser", "password123", "invalid_key")
    assert success is False
    assert "Nieprawidłowy klucz dostępu" in message

def test_authenticate_user_success(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("testuser", "password123", access_key)
    success, message, user = auth_manager.authenticate_user("testuser", "password123")
    assert success is True
    assert "Logowanie pomyślne" in message

def test_authenticate_user_invalid_password(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("testuser", "password123", access_key)
    success, message, _ = auth_manager.authenticate_user("testuser", "wrongpassword")
    assert success is False
    assert "Nieprawidłowa nazwa użytkownika lub hasło" in message

def test_authenticate_user_non_existent(auth_manager):
    success, message, _ = auth_manager.authenticate_user("nonexistent", "password123")
    assert success is False
    assert "Nieprawidłowa nazwa użytkownika lub hasło" in message

def test_generate_access_key(auth_manager):
    key = auth_manager.generate_access_key("test_description", expires_days=7)
    assert isinstance(key, str)
    assert len(key) > 0
    keys = auth_manager.get_access_keys()
    assert any(k["key"] == key for k in keys)
    key_data = next(k for k in keys if k["key"] == key)
    assert key_data["description"] == "test_description"
    assert key_data["is_active"] == 1
    assert key_data["expires_at"] is not None
    
    # Test with no expiry
    key_no_expiry = auth_manager.generate_access_key("no_expiry_key", expires_days=0)
    keys = auth_manager.get_access_keys()
    assert next(k for k in keys if k["key"] == key_no_expiry)["expires_at"] is None

def test_validate_access_key(auth_manager):
    key = auth_manager.generate_access_key("valid_key")
    is_valid, msg = auth_manager.validate_access_key(key)
    assert is_valid is True
    assert msg == ""

    auth_manager.deactivate_access_key(key)
    is_valid, msg = auth_manager.validate_access_key(key)
    assert is_valid is False
    assert "Klucz dostępu został dezaktywowany" in msg

    # Test expired key
    expired_key = auth_manager.generate_access_key("expired_key", expires_days=1) # Generate for 1 day
    
    # Manually update expires_at in DB to be in the past
    conn = get_db_connection(auth_manager.db_path)
    cursor = conn.cursor()
    cursor.execute('UPDATE access_keys SET expires_at = ? WHERE key = ?', 
                   ((datetime.datetime.now() - datetime.timedelta(days=1)).isoformat(), expired_key))
    conn.commit()
    conn.close()

    is_valid, msg = auth_manager.validate_access_key(expired_key)
    assert is_valid is False
    assert "Klucz dostępu wygasł" in msg

def test_deactivate_access_key(auth_manager):
    key = auth_manager.generate_access_key("to_deactivate")
    assert auth_manager.deactivate_access_key(key) is True
    keys = auth_manager.get_access_keys()
    assert next(k for k in keys if k["key"] == key)["is_active"] == 0

def test_delete_access_key(auth_manager):
    key = auth_manager.generate_access_key("to_delete")
    assert auth_manager.delete_access_key(key) is True
    keys = auth_manager.get_access_keys()
    assert not any(k["key"] == key for k in keys)

def test_delete_user(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("user_to_delete", "password123", access_key)
    assert auth_manager.delete_user("user_to_delete") is True
    users = auth_manager.get_all_users()
    assert not any(u["username"] == "user_to_delete" for u in users)

def test_toggle_user_status(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("user_status", "password123", access_key)
    
    user_info = auth_manager.get_user_info("user_status")
    assert user_info["is_active"] == 1

    auth_manager.toggle_user_status("user_status")
    user_info = auth_manager.get_user_info("user_status")
    assert user_info["is_active"] == 0

    auth_manager.toggle_user_status("user_status")
    user_info = auth_manager.get_user_info("user_status")
    assert user_info["is_active"] == 1

def test_update_hubert_coins(auth_manager):
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("coin_user", "password123", access_key)
    
    user_info = auth_manager.get_user_info("coin_user")
    assert user_info["hubert_coins"] == 0

    auth_manager.update_hubert_coins("coin_user", 10)
    user_info = auth_manager.get_user_info("coin_user")
    assert user_info["hubert_coins"] == 10

def test_get_all_users(auth_manager):
    access_key_1 = auth_manager.generate_access_key("key1")
    auth_manager.register_user("user1", "pass123", access_key_1)
    access_key_2 = auth_manager.generate_access_key("key2")
    auth_manager.register_user("user2", "pass123", access_key_2)

    users = auth_manager.get_all_users()
    assert len(users) == 2 # Oczekujemy dokładnie 2 użytkowników, ponieważ baza jest czyszczona przed każdym testem
    assert any(u["username"] == "user1" for u in users)
    assert any(u["username"] == "user2" for u in users)


def test_password_reset_flow(auth_manager):
    # 1. Zarejestruj użytkownika
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("reset_user", "old_password", access_key)

    # 2. Wygeneruj token resetowania hasła
    token = auth_manager.generate_password_reset_token("reset_user")
    assert token is not None

    # 3. Sprawdź, czy token jest prawidłowy
    username = auth_manager.validate_password_reset_token(token)
    assert username == "reset_user"

    # 4. Zresetuj hasło przy użyciu tokena
    success, message = auth_manager.reset_user_password_with_token(token, "new_password")
    assert success is True
    assert "Hasło zostało pomyślnie zresetowane" in message

    # 5. Sprawdź, czy można zalogować się nowym hasłem
    auth_success, _, user = auth_manager.authenticate_user("reset_user", "new_password")
    assert auth_success is True
    assert user is not None

    # 6. Sprawdź, czy nie można zalogować się starym hasłem
    auth_failure, _, user = auth_manager.authenticate_user("reset_user", "old_password")
    assert auth_failure is False
    assert user is None

    # 7. Sprawdź, czy token został unieważniony po użyciu
    username_after_reset = auth_manager.validate_password_reset_token(token)
    assert username_after_reset is None


def test_validate_invalid_or_expired_password_reset_token(auth_manager):
    # Sprawdź nieprawidłowy token
    username = auth_manager.validate_password_reset_token("invalid_token")
    assert username is None

    # Sprawdź wygasły token
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("expired_token_user", "password", access_key)
    token = auth_manager.generate_password_reset_token("expired_token_user")

    # Ręczna zmiana daty wygaśnięcia w bazie danych na przeszłą
    # Używamy istniejącego połączenia z auth_manager, aby uniknąć blokady bazy danych
    cursor = auth_manager.conn.cursor()
    cursor.execute('UPDATE users SET password_reset_expires = ? WHERE username = ?',
                   ((datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(), "expired_token_user"))
    auth_manager.conn.commit()

    username = auth_manager.validate_password_reset_token(token)
    assert username is None


def test_referral_system(auth_manager):
    # 1. Utwórz użytkownika polecającego
    access_key_referrer = auth_manager.generate_access_key("referrer_key")
    auth_manager.register_user("referrer", "password123", access_key_referrer)

    # Sprawdź początkową liczbę monet
    referrer_info = auth_manager.get_user_info("referrer")
    assert referrer_info["hubert_coins"] == 0

    # 2. Utwórz nowego użytkownika z kodem polecającym
    access_key_referred = auth_manager.generate_access_key("referred_key")
    auth_manager.register_user("referred_user", "password123", access_key_referred, referral_code="referrer")

    # 3. Sprawdź, czy użytkownik polecający otrzymał monetę
    referrer_info_after = auth_manager.get_user_info("referrer")
    assert referrer_info_after["hubert_coins"] == 1


def test_notifications_system(auth_manager):
    # 1. Utwórz u��ytkownika
    access_key = auth_manager.generate_access_key("test_key")
    auth_manager.register_user("notification_user", "password123", access_key)

    # 2. Sprawdź powiadomienie powitalne
    notifications = auth_manager.get_notifications("notification_user")
    assert len(notifications) == 1
    assert "Witaj w mObywatel!" in notifications[0]["message"]
    assert notifications[0]["is_read"] == 0

    # 3. Oznacz powiadomienie jako przeczytane
    notification_id = notifications[0]["id"]
    auth_manager.mark_notification_as_read(notification_id)

    # 4. Sprawdź, czy status się zmienił
    notifications_after_read = auth_manager.get_notifications("notification_user")
    assert notifications_after_read[0]["is_read"] == 1





