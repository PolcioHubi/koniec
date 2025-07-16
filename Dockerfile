# Użyj oficjalnego obrazu Pythona jako obrazu bazowego
FROM python:3.12-slim-bookworm

# Ustaw katalog roboczy w kontenerze
WORKDIR /app

# Kopiuj plik requirements.txt i zainstaluj zależności
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiuj resztę kodu aplikacji do katalogu roboczego
COPY . .

# Ustaw zmienną środowiskową dla trybu produkcyjnego
ENV FLASK_ENV=production

# Ustaw zmienną środowiskową dla ścieżki do bazy danych rate limitera (jeśli używasz Redis)
# Jeśli nie używasz Redis, możesz usunąć tę linię lub ustawić na "memory://"
ENV RATELIMIT_STORAGE_URL=redis://redis:6379

# Ustaw zmienne środowiskowe dla danych admina (ZMIEN W PRODUKCJI!)
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=change_this_password_in_production

# Ustaw port, na którym aplikacja będzie nasłuchiwać
EXPOSE 5000

# Komenda uruchamiająca aplikację za pomocą Gunicorna
# Upewnij się, że gunicorn_config.py i wsgi.py są w katalogu /app
CMD ["gunicorn", "--config", "gunicorn_config.py", "wsgi:app"]
