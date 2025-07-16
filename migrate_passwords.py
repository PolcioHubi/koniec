import json
import os
import bcrypt # Dodano import bcrypt

def _hash_password(password: str) -> str:
    # Użycie bcrypt do haszowania
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')

def migrate_passwords(users_file: str):
    try:
        with open(users_file, "r", encoding="utf-8") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print(f"Błąd: Nie można wczytać pliku {users_file}. Tworzenie pustego słownika.")
        users = {}

    migrated_count = 0
    for username, user_data in users.items():
        current_password = user_data.get("password")
        
        # Sprawdzenie czy hasło istnieje i czy NIE jest już haszowane bcrypt
        # Hasze bcrypt zaczynają się od $2b$ lub $2a$ i mają określoną długość
        # To jest uproszczone sprawdzenie, idealnie powinno się użyć bcrypt.checkpw
        # ale do migracji wystarczy sprawdzenie formatu
        if current_password and (not current_password.startswith(("$2b$", "$2a$")) or len(current_password) < 60): # bcrypt hasze są dłuższe niż SHA256
            hashed_password = _hash_password(current_password)
            user_data["password"] = hashed_password
            print(f"Migrowano hasło dla użytkownika: {username}")
            migrated_count += 1
        elif current_password is None:
            print(f"Ostrzeżenie: Użytkownik {username} nie ma hasła. Pomijam migrację.")
        else:
            print(f"Hasło dla użytkownika {username} jest już w formacie bcrypt. Pomijam migrację.")


    if migrated_count > 0:
        with open(users_file, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        print(f"Zakończono migrację. Zmigrowano {migrated_count} haseł.")
    else:
        print("Brak haseł do migracji lub wszystkie hasła są już haszowane.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    users_json_path = os.path.join(script_dir, "auth_data", "users.json")
    migrate_passwords(users_json_path)


