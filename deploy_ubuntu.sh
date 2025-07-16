#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# ==============================================================================

# Zatrzymaj skrypt w przypadku błędu
set -e

# --- ZMIENNE KONFIGURACYJNE (dostosuj do swoich potrzeb) ---
SERVICE_NAME="mobywatel"
PROJECT_USER="ubuntu"
# Pełna ścieżka do katalogu z kodem źródłowym (tam gdzie jest ten skrypt)
SOURCE_DIR="/home/ubuntu/test" # <<< UPEWNIJ SIĘ, ŻE TO POPRAWNA ŚCIEŻKA
# Katalog docelowy, gdzie będzie działać aplikacja
DEST_DIR="/var/www/$SERVICE_NAME"
# Twoja domena (bez https://)
DOMAIN="gov-mobywatel.website"
# Twój adres e-mail dla certyfikatu SSL
SSL_EMAIL="polciohubi19@wp.pl"


echo ">>> START: Rozpoczynanie wdrożenia aplikacji $SERVICE_NAME..."

# --- KROK 1: Instalacja podstawowych zależności ---
echo ">>> KROK 1: Instalowanie Nginx, Pip, Venv i Certbota..."
sudo apt-get update
sudo apt-get install -y nginx python3-pip python3-venv certbot python3-certbot-nginx

# --- KROK 2: Przygotowanie katalogu aplikacji i kopiowanie plików ---
echo ">>> KROK 2: Tworzenie katalogu $DEST_DIR i kopiowanie plików..."
sudo mkdir -p $DEST_DIR
sudo rsync -a --delete "$SOURCE_DIR/" "$DEST_DIR/" --exclude ".git" --exclude "*.pyc" --exclude "__pycache__" --exclude "deploy_ubuntu.sh"
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR

# --- KROK 2.5: Tworzenie katalogu na logi ---
echo ">>> KROK 2.5: Tworzenie katalogu na logi..."
sudo mkdir -p $DEST_DIR/logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/logs

# --- KROK 2.6: Ustawianie uprawnień do plików ---
echo ">>> KROK 2.6: Ustawianie szerokich uprawnień do plików i folderów..."
# UWAGA: Poniższe komendy nadają bardzo szerokie uprawnienia (odczyt/zapis/wykonanie dla wszystkich).
# Jest to często używane do rozwiązywania problemów z dostępem, ale w środowisku produkcyjnym
# zaleca się stosowanie bardziej restrykcyjnych uprawnień (np. 755 dla folderów i 644 dla plików).
sudo find $DEST_DIR -type d -exec chmod 777 {} \;
sudo find $DEST_DIR -type f -exec chmod 666 {} \;

# --- KROK 3: Konfiguracja środowiska wirtualnego Python ---
echo ">>> KROK 3: Tworzenie środowiska wirtualnego i instalacja zależności..."
cd $DEST_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate
cd - # Wróć do poprzedniego katalogu

# --- KROK 4: Konfiguracja usługi Systemd dla Gunicorn ---
echo ">>> KROK 4: Tworzenie pliku usługi /etc/systemd/system/${SERVICE_NAME}.service..."
# Najpierw usuń stary plik usługi, jeśli istnieje, aby uniknąć konfliktów
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Gunicorn instance to serve $SERVICE_NAME
After=network.target

[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
Environment="PATH=$DEST_DIR/venv/bin"
ExecStart=$DEST_DIR/venv/bin/gunicorn --workers 3 --bind unix:$DEST_DIR/${SERVICE_NAME}.sock -m 007 --access-logfile $DEST_DIR/logs/gunicorn_access.log --error-logfile $DEST_DIR/logs/gunicorn_error.log wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- KROK 5: Konfiguracja Nginx ---
echo ">>> KROK 5: Tworzenie konfiguracji Nginx dla domeny $DOMAIN..."
# Najpierw usuń stare pliki konfiguracyjne Nginx, jeśli istnieją
sudo rm -f /etc/nginx/sites-available/$SERVICE_NAME
sudo rm -f /etc/nginx/sites-enabled/$SERVICE_NAME
sudo tee /etc/nginx/sites-available/$SERVICE_NAME > /dev/null <<EOF
# Blok przekierowujący z HTTP na HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

# Główny blok serwera dla HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # Logi Nginx
    access_log $DEST_DIR/logs/nginx_access.log;
    error_log $DEST_DIR/logs/nginx_error.log;

    # Konfiguracja SSL zostanie uzupełniona przez Certbota
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location /static {
        alias $DEST_DIR/static;
    }

    location / {
        proxy_pass http://unix:$DEST_DIR/${SERVICE_NAME}.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Włącz nową konfigurację i usuń domyślną, aby uniknąć konfliktów
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# --- KROK 6: Uruchomienie usług ---
echo ">>> KROK 6: Przeładowanie usług i restart..."
sudo systemctl daemon-reload
sudo systemctl restart $SERVICE_NAME
sudo systemctl enable $SERVICE_NAME
sudo nginx -t
sudo systemctl restart nginx

# --- KROK 7: Konfiguracja SSL za pomocą Certbota ---
echo ">>> KROK 7: Uruchamianie Certbota dla $DOMAIN w trybie non-interactive..."
# Certbot automatycznie wykryje i zaktualizuje konfigurację Nginx
sudo certbot --nginx --non-interactive --agree-tos -m "$SSL_EMAIL" -d "$DOMAIN" --redirect

echo
echo "----------------------------------------------------"
echo "✅ WDROŻENIE ZAKOŃCZONE POMYŚLNIE!"
echo "Twoja strona powinna być dostępna pod adresem: https://$DOMAIN"
echo "Logi aplikacji znajdziesz w: $DEST_DIR/logs/"
echo "----------------------------------------------------"
