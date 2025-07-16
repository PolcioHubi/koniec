from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, send_from_directory
from bs4 import BeautifulSoup
import os
import logging
from logging.handlers import RotatingFileHandler
import logging.config
import json
import re
import hashlib
from datetime import datetime
from functools import wraps
from user_auth import UserAuthManager
from pesel_generator import generate_pesel
from production_config import config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

app = Flask(__name__, static_folder='static', static_url_path='/static')

# ============== Logging Configuration ===============
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'app.log')

# Create a rotating file handler
# This will create a new log file when the current one reaches 5MB, keeping up to 5 old log files.
file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.DEBUG)

# Add the handler to the Flask app's logger
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)

# Also configure the root logger
logging.basicConfig(level=logging.DEBUG, handlers=[file_handler])

app.logger.info('Mobywatel application starting up...')
# ======================================================

# Load configuration based on FLASK_ENV environment variable
app_config = config[os.environ.get('FLASK_ENV', 'development')]
app.config.from_object(app_config)
app_config.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # The name of the view to redirect to when the user needs to log in.

@login_manager.user_loader
def load_user(user_id):
    return auth_manager.get_user_by_id(user_id)

# Initialize database
from database import init_db
init_db()

# Initialize Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"],
    storage_uri="memory://", # Using in-memory storage for simplicity. For production, use Redis or Memcached.
    strategy="fixed-window"
)

# Define the fixed input file path
FIXED_INPUT_FILE = "pasted_content.txt"

# Initialize user authentication manager
auth_manager = UserAuthManager()

# Admin credentials (in production, use a proper authentication system)
# These should ideally be loaded from environment variables or a secure vault
ADMIN_CREDENTIALS = {
    os.environ.get("ADMIN_USERNAME", "admin"): os.environ.get("ADMIN_PASSWORD", "change_this_password_in_production")
}

# Global error handler for HTTP errors
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(e):
    code = getattr(e, 'code')
    message = getattr(e, 'description')
    if code == 404:
        message = 'Resource not found.'
    elif code == 401:
        message = 'Unauthorized access.'
    elif code == 400:
        message = 'Bad request.'
    
    logging.error(f"HTTP Error {code}: {message}", exc_info=True)
    response = jsonify({'success': False, 'error': message})
    response.status_code = code
    return response

def require_admin_login(f):
    """Decorator to require admin login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

def get_folder_size(folder_path):
    """Calculate total size of a folder"""
    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.path.exists(filepath):
                    total_size += os.path.getsize(filepath)
    except OSError as e:
        logging.error(f"Error getting folder size for {folder_path}: {e}")
        pass
    return total_size

def get_user_stats():
    """Get statistics about all users"""
    user_data_dir = "user_data"
    if not os.path.exists(user_data_dir):
        return {
            "total_users": 0,
            "total_files": 0,
            "total_size": 0
        }
    
    total_users = 0
    total_files = 0
    total_size = 0
    
    try:
        for user_folder in os.listdir(user_data_dir):
            user_path = os.path.join(user_data_dir, user_folder)
            if os.path.isdir(user_path):
                total_users += 1
                
                # Count files in user folder
                files_folder = os.path.join(user_path, "files")
                if os.path.exists(files_folder):
                    for file in os.listdir(files_folder):
                        file_path = os.path.join(files_folder, file)
                        if os.path.isfile(file_path):
                            total_files += 1
                            total_size += os.path.getsize(file_path)
    except OSError as e:
        logging.error(f"Error getting user stats: {e}")
    
    return {
        "total_users": total_users,
        "total_files": total_files,
        "total_size": total_size
    }

def create_user_folder(user_name):
    """Create user-specific folders for files and logs"""
    user_data_dir = "user_data"
    user_folder = os.path.join(user_data_dir, user_name)
    files_folder = os.path.join(user_folder, "files")
    logs_folder = os.path.join(user_folder, "logs")
    
    os.makedirs(files_folder, exist_ok=True)
    os.makedirs(logs_folder, exist_ok=True)

    return user_folder, files_folder, logs_folder

def get_user_files(user_name):
    """Get list of user files with metadata"""
    try:
        _, files_folder, _ = create_user_folder(user_name)
        
        if not os.path.exists(files_folder):
            return []
        
        files = []
        for filename in os.listdir(files_folder):
            filepath = os.path.join(files_folder, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    "name": filename,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "path": filepath
                })
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: x["modified"], reverse=True)
        return files
    except Exception as e:
        logging.error(f"Error getting user files for {user_name}: {e}", exc_info=True)
        return []

def get_all_users():
    """Get list of all users with their statistics"""
    user_data_dir = "user_data"
    if not os.path.exists(user_data_dir):
        return []
    
    users = []
    try:
        for user_folder in os.listdir(user_data_dir):
            user_path = os.path.join(user_data_dir, user_folder)
            if os.path.isdir(user_path):
                total_files = 0
                total_size = 0
                last_activity = None

                # Count files in user folder
                files_folder = os.path.join(user_path, "files")
                if os.path.exists(files_folder):
                    for file in os.listdir(files_folder):
                        file_path = os.path.join(files_folder, file)
                        if os.path.isfile(file_path):
                            total_files += 1
                            total_size += os.path.getsize(file_path)
                            
                            # Get last modification time
                            mtime = os.path.getmtime(file_path)
                            if last_activity is None or mtime > last_activity:
                                last_activity = mtime
                
                # Get last activity from logs
                log_file = os.path.join(user_path, "logs", "actions.log") # Corrected path
                if os.path.exists(log_file):
                    log_mtime = os.path.getmtime(log_file)
                    if last_activity is None or log_mtime > last_activity:
                        last_activity = log_mtime
                
                users.append({
                    "name": user_folder,
                    "file_count": total_files,
                    "total_size": total_size,
                    "last_activity": datetime.fromtimestamp(last_activity).isoformat() if last_activity else None,
                    "created_date": datetime.fromtimestamp(os.path.getctime(user_path)).isoformat() if os.path.exists(user_path) else None
                })
    except OSError as e:
        logging.error(f"Error getting all users: {e}")
    
    # Sort by last activity (most recent first)
    users.sort(key=lambda x: x["last_activity"] or "", reverse=True)
    return users

def replace_html_data(input_soup, new_data):
    """
    Replace data in HTML using BeautifulSoup
    Safely handles None values by converting them to empty strings
    """
    # Helper function to safely get value from new_data
    def safe_get(key, default=''):
        value = new_data.get(key, default)
        return str(value) if value is not None else default
    
    # This function will contain the data replacement logic
    # It takes a BeautifulSoup object (input_soup) and new_data dictionary
    # and modifies the soup in place.

    # Dane w sekcji main (id='praw')
    # Używamy find_previous_sibling, aby znaleźć element <p> przed etykietą
    
    # Imię
    name_label = input_soup.find('p', class_='sub', string='Imię (Imiona)')
    if name_label:
        name_value = name_label.find_previous_sibling('p')
        if name_value:
            name_value.string = safe_get('imie')
    
    # Nazwisko
    surname_label = input_soup.find('p', class_='sub', string='Nazwiskо')
    if surname_label:
        surname_value = surname_label.find_previous_sibling('p')
        if surname_value:
            surname_value.string = safe_get('nazwisko')

    # Obywatelstwo
    citizenship_label = input_soup.find('p', class_='sub', string='Obywatelstwo')
    if citizenship_label:
        citizenship_value = citizenship_label.find_previous_sibling('p')
        if citizenship_value:
            citizenship_value.string = safe_get('obywatelstwo')

    # Data urodzenia
    dob_label = input_soup.find('p', class_='sub', string='Data urodzenia')
    if dob_label:
        dob_value = dob_label.find_previous_sibling('p')
        if dob_value:
            dob_value.string = safe_get('data_urodzenia')

    # Numer PESEL
    pesel_label = input_soup.find('p', class_='sub', string='Numer PЕSEL')
    if pesel_label:
        pesel_value = pesel_label.find_previous_sibling('p')
        if pesel_value:
            pesel_value.string = safe_get('pesel')

    # Dane w sekcji danebox (główne dane mDowodu)
    # Seria i numer
    seria_numer_mdowod_label = input_soup.find("p", class_="info", string=re.compile(r"Seri. i numer"))
    if seria_numer_mdowod_label:
        seria_numer_mdowod_value = seria_numer_mdowod_label.find_next_sibling("p", class_="main")
        if seria_numer_mdowod_value:
            seria_numer_mdowod_value.string = safe_get("seria_numer_mdowodu")

    # Termin ważności
    termin_waznosci_mdowod_label = input_soup.find("p", class_="info", string=re.compile(r"Termin w[aа]żno[śs]ci"))
    if termin_waznosci_mdowod_label:
        termin_waznosci_mdowod_value = termin_waznosci_mdowod_label.find_next_sibling("p", class_="main")
        if termin_waznosci_mdowod_value:
            termin_waznosci_mdowod_value.string = safe_get("termin_waznosci_mdowodu")

    # Data wydania
    data_wydania_mdowod_label = input_soup.find("p", class_="info", string=re.compile(r"Data wydani[aа]"))
    if data_wydania_mdowod_label:
        data_wydania_mdowod_value = data_wydania_mdowod_label.find_next_sibling("p", class_="main")
        if data_wydania_mdowod_value:
            data_wydania_mdowod_value.string = safe_get("data_wydania_mdowodu")

    # Imię ojca
    imie_ojca_mdowod_label = input_soup.find('p', class_='info', string='Imię ojcа')
    if imie_ojca_mdowod_label:
        imie_ojca_mdowod_value = imie_ojca_mdowod_label.find_next_sibling('p', class_='main')
        if imie_ojca_mdowod_value:
            imie_ojca_mdowod_value.string = safe_get('imie_ojca_mdowod')

    # Imię matki
    imie_matki_mdowod_label = input_soup.find('p', class_='info', string='Imię mаtki')
    if imie_matki_mdowod_label:
        imie_matki_mdowod_value = imie_matki_mdowod_label.find_next_sibling('p', class_='main')
        if imie_matki_mdowod_value:
            imie_matki_mdowod_value.string = safe_get('imie_matki_mdowod')

    # Dane w sekcji danedowodu (dane dowodu osobistego)
    # Seria i numer
    seria_numer_dowod_section = input_soup.find('section', id='danedowodu')
    if seria_numer_dowod_section:
        # Seria i numer
        seria_numer_dowod_label = seria_numer_dowod_section.find("p", class_="info", string=re.compile(r"S[eе]ria i numer"))
        if seria_numer_dowod_label:
            seria_numer_dowod_value = seria_numer_dowod_label.find_next_sibling("p", class_="main")
            if seria_numer_dowod_value:
                seria_numer_dowod_value.string = safe_get("seria_numer_dowodu")

        # Termin ważności
        termin_waznosci_dowod_label = seria_numer_dowod_section.find("p", class_="info", string="Tеrmin ważności")
        if termin_waznosci_dowod_label:
            termin_waznosci_dowod_value = termin_waznosci_dowod_label.find_next_sibling("p", class_="main")
            if termin_waznosci_dowod_value:
                termin_waznosci_dowod_value.string = safe_get("termin_waznosci_dowodu")

        # Data wydania
        data_wydania_dowod_label = seria_numer_dowod_section.find("p", class_="info", string=re.compile(r"Data wydani."))
        if data_wydania_dowod_label:
            data_wydania_dowod_value = data_wydania_dowod_label.find_next_sibling("p", class_="main")
            if data_wydania_dowod_value:
                data_wydania_dowod_value.string = safe_get("data_wydania_dowodu")

    # Dane w sekcji rogo (dodatkowe dane)
    # Płeć
    plec_label = input_soup.find('p', class_='info', string='Płеć')
    if plec_label:
        plec_value = plec_label.find_next_sibling('p', class_='main')
        if plec_value:
            gender_map = {
                "M": "Mężczyzna",
                "K": "Kobieta"
            }
            plec_value.string = gender_map.get(safe_get("plec"), safe_get("plec"))

    # Nazwisko rodowe
    nazwisko_rodowe_label = input_soup.find("p", class_="info", string="Nazwisko rodowe")
    if nazwisko_rodowe_label:
        nazwisko_rodowe_value = nazwisko_rodowe_label.find_next_sibling("p", class_="main")
        if nazwisko_rodowe_value:
            nazwisko_rodowe_value.string = safe_get("nazwisko_rodowe").capitalize()

    # Nazwisko rodowe ojca
    nazwisko_rodowe_ojca_label = input_soup.find("p", class_="info", string="Nazwiskо rodowе ojca")
    if nazwisko_rodowe_ojca_label:
        nazwisko_rodowe_ojca_value = nazwisko_rodowe_ojca_label.find_next_sibling("p", class_="main")
        if nazwisko_rodowe_ojca_value:
            nazwisko_rodowe_ojca_value.string = safe_get("nazwisko_rodowe_ojca").capitalize()

    # Nazwisko rodowe matki
    nazwisko_rodowe_matki_label = input_soup.find("p", class_="info", string="Nazwiskо rodowе matki")
    if nazwisko_rodowe_matki_label:
        nazwisko_rodowe_matki_value = nazwisko_rodowe_matki_label.find_next_sibling("p", class_="main")
        if nazwisko_rodowe_matki_value:
            nazwisko_rodowe_matki_value.string = safe_get("nazwisko_rodowe_matki").capitalize()

    # Miejsce urodzenia
    miejsce_urodzenia_label = input_soup.find("p", class_="info", string="Miejsce urоdzenia")
    if miejsce_urodzenia_label:
        miejsce_urodzenia_value = miejsce_urodzenia_label.find_next_sibling("p", class_="main")
        if miejsce_urodzenia_value:
            miejsce_urodzenia_value.string = safe_get("miejsce_urodzenia").capitalize()

    # Adres zameldowania
    adres_zameldowania_label = input_soup.find("p", class_="info", string="Аdres zameldоwania na pobyt stały")
    if adres_zameldowania_label:
        adres_zameldowania_value = adres_zameldowania_label.find_next_sibling("p", class_="main")
        if adres_zameldowania_value:
            adres_zameldowania_value.string = safe_get("adres_zameldowania").capitalize()

    # Data zameldowania
    data_zameldowania_label = input_soup.find("p", class_="info", string="Data zameldоwaniа na pobyt stały")
    if data_zameldowania_label:
        data_zameldowania_value = data_zameldowania_label.find_next_sibling("p", class_="main")
        if data_zameldowania_value:
            data_zameldowania_value.string = safe_get("data_zameldowania").capitalize()
    return input_soup

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file"""
    if not os.path.exists(filepath):
        return None
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b'') :
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {filepath}: {e}")
        return None

@app.route("/set_user", methods=["POST"])
def set_user():
    """Set user name in session"""
    try:
        data = request.get_json()
        user_name = data.get('user_name')
        
        if not user_name:
            return jsonify({'success': False, 'error': 'Nazwa użytkownika jest wymagana'})
        
        # Validate user name (basic validation)
        if len(user_name) < 2 or len(user_name) > 50:
            return jsonify({'success': False, 'error': 'Nazwa użytkownika musi mieć od 2 do 50 znaków'})
        
        # Store in session
        session['user_name'] = user_name
        
        # Create user folder
        create_user_folder(user_name)
        logging.info("User set username", extra={'user': user_name, 'ip': request.environ.get('REMOTE_ADDR')})
        
        return jsonify({'success': True, 'message': 'Nazwa użytkownika ustawiona pomyślnie'})
    except Exception as e:
        logging.error(f"Error setting user name: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas ustawiania nazwy użytkownika'})

@app.route("/get_example_data", methods=["GET"])
def get_example_data():
    """Return example data for form filling"""
    example_data = {
        'imie': 'Jan',
        'nazwisko': 'Kowalski',
        'obywatelstwo': 'Polskie',
        'data_urodzenia': '01.01.1990',
        'pesel': '90010112345'
    }
    return jsonify(example_data)

@app.route("/generate_pesel", methods=["POST"])
def handle_generate_pesel():
    """Generate PESEL number based on birth date and gender"""
    try:
        data = request.get_json()
        birth_date = data.get('birth_date')
        gender = data.get('gender')
        
        if not birth_date or not gender:
            return jsonify({'success': False, 'error': 'Data urodzenia i płeć są wymagane'})
        
        # Użycie funkcji generate_pesel z pesel_generator.py
        pesel = generate_pesel(birth_date, gender)
        
        return jsonify({'success': True, 'pesel': pesel})
    except Exception as e:
        logging.error(f"Error generating PESEL: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas generowania numeru PESEL'})

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route("/forgot_password", methods=["POST"])
@limiter.limit("5 per minute")
def forgot_password():
    try:
        data = request.get_json()
        username = data.get("username", "").strip()

        if not username:
            return jsonify({"success": False, "error": "Nazwa użytkownika jest wymagana"}), 400

        token = auth_manager.generate_password_reset_token(username)
        if token:
            # In a real application, you would send this token via email
            logging.info(f"Password reset token generated for {username}: {token}")
            return jsonify({"success": True, "message": "Jeśli użytkownik istnieje, link do resetowania hasła został wysłany.", "token": token}) # For demonstration, return token
        else:
            return jsonify({"success": False, "error": "Nie znaleziono użytkownika lub wystąpił błąd"}), 404
    except Exception as e:
        logging.error(f"Error in forgot password: {e}")
        return jsonify({"success": False, "error": "Wystąpił błąd podczas przetwarzania żądania"}), 500

@app.before_request
def log_request_info():
    """Log information about each incoming request."""
    app.logger.debug(f'Request: {request.method} {request.path} from {request.remote_addr}')
    # To log form data or JSON, you can add more logic here, but be careful with sensitive data
    # For example:
    # if request.is_json:
    #     app.logger.debug(f'Request JSON: {request.get_json(silent=True)}')
    # else:
    #     app.logger.debug(f'Request Form: {request.form.to_dict()}')

@app.route("/reset_password", methods=["POST"])
@limiter.limit("5 per minute")
def reset_password():
    try:
        data = request.get_json()
        token = data.get("token", "").strip()
        new_password = data.get("new_password", "")

        if not token or not new_password:
            return jsonify({"success": False, "error": "Token i nowe hasło są wymagane"}), 400

        success, message = auth_manager.reset_user_password_with_token(token, new_password)
        if success:
            logging.info(f"Password reset successful with token: {token}")
            return jsonify({"success": True, "message": message})
        else:
            logging.warning(f"Password reset failed with token: {token} - {message}")
            return jsonify({"success": False, "error": message}), 400
    except Exception as e:
        logging.error(f"Error in reset password: {e}")
        return jsonify({"success": False, "error": "Wystąpił błąd podczas resetowania hasła"}), 500

@app.route("/recover_password_page")
def recover_password_page():
    return render_template("recover_password_page.html")

@app.route("/recover_password", methods=["POST"])
@limiter.limit("5 per minute")
def recover_password():
    try:
        data = request.get_json()
        username = data.get("username", "").strip()
        recovery_token = data.get("recovery_token", "").strip()
        new_password = data.get("new_password", "")

        if not username or not recovery_token or not new_password:
            return jsonify({"success": False, "error": "Wszystkie pola są wymagane"}), 400

        success, message = auth_manager.reset_password_with_recovery_token(username, recovery_token, new_password)
        if success:
            logging.info(f"Password recovered for user: {username}")
            return jsonify({"success": True, "message": message})
        else:
            logging.warning(f"Password recovery failed for user: {username} - {message}")
            return jsonify({"success": False, "error": message}), 400
    except Exception as e:
        logging.error(f"Error in recover password: {e}")
        return jsonify({"success": False, "error": "Wystąpił błąd podczas odzyskiwania hasła"}), 500

@app.before_request
def check_user_status():
    # Exclude routes that don't require login or are part of the login/logout process
    if request.endpoint in ['login', 'register', 'logout', 'admin_login', 'static', 'health_check', 'set_user', 'get_example_data', 'handle_generate_pesel', 'forgot_password', 'reset_password', 'recover_password_page']:
        return

    # Flask-Login handles user session management.
    # This function can be used for other global checks if needed,
    # but manual session management is removed to avoid conflicts.
    if current_user.is_authenticated and not current_user.is_active:
        logout_user()
        logging.warning(f"Deactivated user {current_user.username} attempted to access protected route. Session cleared.")
        return redirect(url_for('login', message='Twoje konto zostało dezaktywowane lub usunięte. Zaloguj się ponownie.'))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == 'POST':
        try:
            # Get user name from form
            user_name = request.form.get('user_name')
            
            if not user_name:
                return jsonify({'success': False, 'error': 'Nazwa użytkownika jest wymagana'})
            
            # Create user folders if they don't exist
            user_folder, files_folder, logs_folder = create_user_folder(user_name)
            
            output_filename = 'dowodnowy.html'
            output_filepath = os.path.join(files_folder, output_filename)

            # Determine the base HTML content to modify
            if os.path.exists(output_filepath):
                # If dowodnowy.html already exists for this user, load it
                input_filepath = output_filepath
            else:
                # Otherwise, use the fixed base template
                input_filepath = os.path.join(os.getcwd(), FIXED_INPUT_FILE)
            
            try:
                with open(input_filepath, 'r', encoding='utf-8') as f:
                    soup = BeautifulSoup(f, 'html.parser')
            except FileNotFoundError:
                logging.error(f"Input file {input_filepath} not found.")
                return jsonify({'success': False, 'error': f"Plik wejściowy {input_filepath} nie został znaleziony."})

            # Collect data from form
            new_data = {
                'imie': request.form.get('imie'),
                'nazwisko': request.form.get('nazwisko'),
                'obywatelstwo': request.form.get('obywatelstwo'),
                'data_urodzenia': request.form.get('data_urodzenia'),
                'pesel': request.form.get('pesel'),
                'seria_numer_mdowodu': request.form.get('seria_numer_mdowodu'),
                'termin_waznosci_mdowodu': request.form.get('termin_waznosci_mdowodu'),
                'data_wydania_mdowodu': request.form.get('data_wydania_mdowodu'),
                'imie_ojca_mdowod': request.form.get('imie_ojca_mdowod'),
                'imie_matki_mdowod': request.form.get('imie_matki_mdowod'),
                'seria_numer_dowodu': request.form.get('seria_numer_dowodu'),
                'termin_waznosci_dowodu': request.form.get('termin_waznosci_dowodu'),
                'data_wydania_dowodu': request.form.get('data_wydania_dowodu'),
                'nazwisko_rodowe': request.form.get('nazwisko_rodowe'),
                'plec': request.form.get('plec'),
                'nazwisko_rodowe_ojca': request.form.get('nazwisko_rodowe_ojca'),
                'nazwisko_rodowe_matki': request.form.get('nazwisko_rodowe_matki'),
                'miejsce_urodzenia': request.form.get('miejsce_urodzenia'),
                'adres_zameldowania': request.form.get('adres_zameldowania'),
                'data_zameldowania': request.form.get('data_zameldowania'),
            }

            # Handle image upload
            image_file = request.files.get('image_upload')
            image_saved = False
            image_filename = 'zdjecie_686510da4d2591.91511191.jpg'
            image_filepath = os.path.join(files_folder, image_filename) # Initialize here

            # Initialize image_filename in new_data based on whether the file exists on disk
            if os.path.exists(image_filepath):
                new_data['image_filename'] = image_filename
            else:
                new_data['image_filename'] = None # Default to None if no image exists

            if image_file and image_file.filename != '':
                logging.info(f"Image file received: {image_file.filename}")
                logging.info(f"User name from session: {user_name}")
                # Validate file type and size
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                logging.info(f"Debug: app.config.get('MAX_CONTENT_LENGTH') raw value: {app.config.get('MAX_CONTENT_LENGTH')}, type: {type(app.config.get('MAX_CONTENT_LENGTH'))}")
                max_file_size = int(app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024))

                file_extension = image_file.filename.rsplit('.', 1)[1].lower() if '.' in image_file.filename else ''
                if file_extension not in allowed_extensions:
                    return jsonify({'success': False, 'error': 'Nieprawidłowy format pliku obrazu. Dozwolone: png, jpg, jpeg, gif.'})

                image_file.seek(0, os.SEEK_END)
                file_size = image_file.tell()
                image_file.seek(0)

                if file_size > max_file_size:
                    return jsonify({'success': False, 'error': f'Rozmiar pliku przekracza dozwolony limit {max_file_size / (1024 * 1024):.0f}MB.'})

                new_image_hash = hashlib.sha256(image_file.read()).hexdigest()
                image_file.seek(0)

                old_image_hash = calculate_file_hash(image_filepath)

                if new_image_hash != old_image_hash:
                    image_file.save(image_filepath)
                    logging.info("Image uploaded and updated", extra={
                        'user': user_name,
                        'file': image_filename,
                        'size_bytes': os.path.getsize(image_filepath),
                        'ip': request.environ.get('REMOTE_ADDR')
                    })
                    new_data['image_filename'] = image_filename # Ensure it's set after successful save
                else:
                    logging.info("Image uploaded but not changed", extra={
                        'user': user_name,
                        'file': image_filename,
                        'ip': request.environ.get('REMOTE_ADDR')
                    })
            else:
                logging.info("No image file uploaded or filename is empty.")
                # If no image file is uploaded, and no existing file, new_data['image_filename'] will be None
                pass

            # Log the form submission with detailed analytics
            logging.info("User filled form", extra={'user': user_name, 'form_data': new_data})

            
            
            
            
            # Save last submitted data for pre-filling
            last_data_filepath = os.path.join(logs_folder, "last_form_data.json")
            with open(last_data_filepath, 'w', encoding='utf-8') as f:
                json.dump(new_data, f, ensure_ascii=False, indent=2)

            logging.info(f"New data received from form: {new_data}")
            modified_soup = replace_html_data(soup, new_data)
            
            # Check if HTML content has changed
            html_content_changed = False
            new_html_content = str(modified_soup)
            if os.path.exists(output_filepath):
                with open(output_filepath, 'r', encoding='utf-8') as f:
                    old_html_content = f.read()
                if old_html_content != new_html_content:
                    html_content_changed = True
            else:
                html_content_changed = True

            if html_content_changed:
                with open(output_filepath, 'w', encoding='utf-8') as f:
                    f.write(new_html_content)
                logging.info("HTML file modified", extra={'user': user_name, 'file': output_filename})

            
            
            # Update the image source in the HTML
            img_tag = modified_soup.find('img', id='user_photo')
            if img_tag:
                img_tag['src'] = url_for('user_files', filename=image_filename)
            
            # Instead of sending the file, return a success message
            return jsonify({'success': True, 'message': 'Dane i pliki zostały przetworzone pomyślnie.'})

        except Exception as e:
            logging.error(f"Error in index POST request: {e}", exc_info=True) # Log full traceback
            return jsonify({'success': False, 'error': 'Wystąpił błąd podczas przetwarzania danych.'})

    # Sprawdź czy użytkownik jest zalogowany
    last_form_data = {}

    if current_user.is_authenticated:
        _, _, logs_folder = create_user_folder(current_user.username)
        last_data_filepath = os.path.join(logs_folder, "last_form_data.json")
        if os.path.exists(last_data_filepath):
            try:
                with open(last_data_filepath, 'r', encoding='utf-8') as f:
                    last_form_data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                last_form_data = {}

    # Fetch user statistics
    all_users = auth_manager.get_all_users()
    total_registered_users = len(all_users)
    active_users = [user for user in all_users if user.get('is_active') == 1]
    num_active_users = len(active_users)

    top_user = None
    if all_users:
        top_user = max(all_users, key=lambda user: user.get('hubert_coins', 0))

    return render_template('index.html', 
                           user_logged_in=current_user.is_authenticated, 
                           username=current_user.username if current_user.is_authenticated else None,
                           total_registered_users=total_registered_users,
                           num_active_users=num_active_users,
                           top_user=top_user,
                           last_form_data=last_form_data)

@app.route("/admin/")
@require_admin_login
def admin():
    return render_template("admin_enhanced.html")

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("100 per minute") # Limit admin login attempts
def admin_login():
    if request.method == "POST":
        try:
            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
            
            if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
                session["admin_logged_in"] = True
                session["admin_username"] = username
                logging.info(f"Admin login successful for user: {username}")
                return jsonify({"success": True, "message": "Logowanie pomyślne"})
            else:
                logging.warning(f"Failed admin login attempt for user: {username}")
                return jsonify({"success": False, "error": "Nieprawidłowe dane logowania"}), 401
        except Exception as e:
            logging.error(f"Error in admin login: {e}")
            return jsonify({"success": False, "error": "Wystąpił błąd podczas logowania"}), 500
    
    return render_template("admin_login.html")

@app.route("/admin/logout")
@require_admin_login
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))

@app.route("/admin/api/users")
@require_admin_login
def api_get_users():
    try:
        users = get_all_users()
        stats = get_user_stats()
        return jsonify({
            "success": True,
            "users": users,
            "stats": stats
        })
    except Exception as e:
        logging.error(f"Error getting users: {e}")
        return jsonify({"success": False, "error": "Wystąpił błąd podczas pobierania danych użytkowników"}), 500

def is_safe_path(basedir, path, follow_symlinks=True):
    # Rozwiązuje symboliczne linki
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))

@app.route("/admin/api/user-logs/<username>")
@require_admin_login
def api_get_user_logs(username):
    # SCIEZKA KRYTYCZNA: Walidacja nazwy uzytkownika, aby zapobiec Path Traversal
    if not is_safe_path(os.path.abspath("user_data"), os.path.abspath(os.path.join("user_data", username))):
        logging.warning(f"Potencjalna proba ataku Path Traversal na uzytkownika: {username}")
        return jsonify({"success": False, "error": "Nieprawidlowa nazwa uzytkownika"}), 400
    try:
        # UWAGA: Logi są teraz scentralizowane. Ta funkcja zwraca tylko pliki.
        # W przyszłości można zaimplementować przeszukiwanie centralnego pliku logów.
        logs = []
        submissions = []
        files = get_user_files(username)
        
        return jsonify({
            "success": True,
            "logs": logs,
            "submissions": submissions,
            "files": files
        })
    except Exception as e:
        logging.error(f"Error getting user logs for {username}: {e}", exc_info=True)
        return jsonify({"success": False, "error": f"Wystapil blad podczas pobierania logow uzytkownika {username}"}), 500

@app.route("/admin/api/download-user/<username>")
@require_admin_login
def api_download_user_data(username):
    # SCIEZKA KRYTYCZNA: Walidacja nazwy uzytkownika, aby zapobiec Path Traversal
    if not is_safe_path(os.path.abspath("user_data"), os.path.abspath(os.path.join("user_data", username))):
        logging.warning(f"Potencjalna proba ataku Path Traversal na uzytkownika: {username}")
        return jsonify({"success": False, "error": "Nieprawidlowa nazwa uzytkownika"}), 400
    try:
        import zipfile
        import tempfile
        
        # Create temporary zip file
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, f"{username}_data.zip")
        
        user_folder = os.path.join("user_data", username)
        if not os.path.exists(user_folder):
            return jsonify({"error": "Użytkownik nie istnieje"}), 404
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(user_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, user_folder)
                    zipf.write(file_path, arcname)
        
        return send_file(zip_path, as_attachment=True, download_name=f"{username}_data.zip")
    except Exception as e:
        logging.error(f"Error downloading user data for {username}: {e}")
        return jsonify({"error": f"Wystąpił błąd podczas pobierania danych użytkownika {username}"}), 500

@app.route("/admin/api/delete-registered-user/<username>", methods=["DELETE"])
@require_admin_login
def api_delete_registered_user(username):
    # SCIEZKA KRYTYCZNA: Walidacja nazwy uzytkownika, aby zapobiec Path Traversal
    if not is_safe_path(os.path.abspath("user_data"), os.path.abspath(os.path.join("user_data", username))):
        logging.warning(f"Potencjalna proba ataku Path Traversal na uzytkownika: {username}")
        return jsonify({"success": False, "error": "Nieprawidlowa nazwa uzytkownika"}), 400
    try:
        import shutil
        
        user_deleted = auth_manager.delete_user(username)
        
        user_folder = os.path.join("user_data", username)
        folder_deleted = False
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
            folder_deleted = True
        
        if user_deleted or folder_deleted:
            logging.info(f"Admin deleted user: {username}")
            return jsonify({"success": True, "message": f"Użytkownik {username} został usunięty"})
        else:
            return jsonify({"success": False, "error": "Użytkownik nie istnieje"}), 404
    except Exception as e:
        logging.error(f"Error deleting user {username}: {e}")
        return jsonify({"success": False, "error": f"Wystąpił błąd podczas usuwania użytkownika {username}"}), 500

@app.route("/admin/api/delete-user-files/<username>", methods=["DELETE"])
@require_admin_login
def api_delete_user_files(username):
    # SCIEZKA KRYTYCZNA: Walidacja nazwy uzytkownika
    if not is_safe_path(os.path.abspath("user_data"), os.path.abspath(os.path.join("user_data", username))):
        logging.warning(f"Potencjalna proba ataku Path Traversal na uzytkownika: {username}")
        return jsonify({"success": False, "error": "Nieprawidlowa nazwa uzytkownika"}), 400
    try:
        import shutil
        user_folder = os.path.join("user_data", username)
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)
            logging.info(f"Admin deleted files for user: {username}")
            return jsonify({"success": True, "message": f"Pliki użytkownika {username} zostały usunięte"})
        else:
            return jsonify({"success": False, "error": "Katalog plików użytkownika nie istnieje"}), 404
    except Exception as e:
        logging.error(f"Error deleting user files for {username}: {e}")
        return jsonify({"success": False, "error": f"Wystąpił błąd podczas usuwania plików użytkownika {username}"}), 500

# API endpoints for access key management
@app.route("/admin/api/access-keys", methods=["GET"])
@require_admin_login
def api_get_access_keys():
    try:
        keys = auth_manager.get_all_access_keys()
        return jsonify({"success": True, "access_keys": keys})
    except Exception as e:
        logging.error(f"Error getting access keys: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/admin/api/generate-access-key", methods=["POST"])
@require_admin_login
def api_generate_access_key():
    try:
        data = request.get_json()
        description = data.get('description')
        validity_days = data.get('validity_days')
        
        key = auth_manager.generate_access_key(description, validity_days)
        return jsonify({'success': True, 'access_key': key})
    except Exception as e:
        logging.error(f"Error generating access key: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas generowania klucza dostępu'})

@app.route("/admin/api/deactivate-access-key", methods=["POST"])
@require_admin_login
def api_deactivate_access_key():
    try:
        data = request.get_json()
        key = data.get("access_key")
        
        success = auth_manager.deactivate_access_key(key)
        if success:
            return jsonify({'success': True, 'message': 'Klucz dostępu dezaktywowany pomyślnie'})
        else:
            return jsonify({'success': False, 'error': 'Klucz dostępu nie został znaleziony lub jest już nieaktywny'})
    except Exception as e:
        logging.error(f"Error deactivating access key: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas dezaktywacji klucza dostępu'})

@app.route("/admin/api/delete-access-key", methods=["DELETE"])
@require_admin_login
def api_delete_access_key():
    try:
        data = request.get_json()
        key = data.get("access_key")
        
        success = auth_manager.delete_access_key(key)
        if success:
            return jsonify({'success': True, 'message': 'Klucz dostępu usunięty pomyślnie'})
        else:
            return jsonify({'success': False, 'error': 'Klucz dostępu nie został znaleziony'})
    except Exception as e:
        logging.error(f"Error deleting access key: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas usuwania klucza dostępu'})

# API endpoints for registered users management
@app.route("/admin/api/registered-users", methods=["GET"])
@require_admin_login
def api_get_registered_users():
    try:
        users = auth_manager.get_all_users(include_passwords=True)
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        logging.error(f"Error getting registered users: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas pobierania zarejestrowanych użytkowników'})

@app.route("/admin/api/toggle-user-status", methods=["POST"])
@require_admin_login
def api_toggle_user_status():
    try:
        data = request.get_json()
        username = data.get('username')
        
        success = auth_manager.toggle_user_status(username)
        if success:
            return jsonify({'success': True, 'message': f'Status użytkownika {username} został zmieniony.'})
        else:
            return jsonify({'success': False, 'error': 'Użytkownik nie został znaleziony'})
    except Exception as e:
        logging.error(f"Error toggling user status: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas zmiany statusu użytkownika'})

@app.route("/admin/api/update-hubert-coins", methods=["POST"])
@require_admin_login
def api_update_hubert_coins():
    try:
        data = request.get_json()
        username = data.get('username')
        amount = data.get('amount')
        
        if not username or not isinstance(amount, int):
            return jsonify({'success': False, 'error': 'Nieprawidłowe dane'}), 400
        
        success = auth_manager.update_hubert_coins(username, amount)
        
        if success:
            return jsonify({'success': True, 'message': f'Zaktualizowano Hubert Coiny dla {username}'})
        else:
            return jsonify({'success': False, 'error': 'Nie znaleziono użytkownika'}), 404
            
    except Exception as e:
        logging.error(f"Error updating Hubert Coins: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas aktualizacji Hubert Coinów'}), 500

@app.route("/admin/api/reset-password", methods=["POST"])
@require_admin_login
def api_reset_user_password():
    try:
        data = request.get_json()
        username = data.get('username')
        new_password = data.get('new_password')

        if not username or not new_password:
            return jsonify({'success': False, 'error': 'Nazwa użytkownika i nowe hasło są wymagane'}), 400
        
        success, message = auth_manager.reset_user_password(username, new_password)

        if success:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message}), 400
    except Exception as e:
        logging.error(f"Error resetting user password: {e}")
        return jsonify({'success': False, 'error': 'Wystąpił błąd podczas resetowania hasła użytkownika'}), 500

# User authentication routes
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute") # Limit registration attempts
def register():
    all_users = auth_manager.get_all_users()
    total_registered_users = len(all_users)
    active_users = [user for user in all_users if user.get('is_active') == 1]
    num_active_users = len(active_users)

    top_user = None
    if all_users:
        top_user = max(all_users, key=lambda user: user.get('hubert_coins', 0))

    if request.method == "POST":
        try:
            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
            access_key = data.get("access_key", "").strip()
            referral_code = data.get("referral_code", "").strip()
            
            # Validation
            if not username or not password or not access_key:
                return jsonify({"success": False, "error": "Wszystkie pola są wymagane"}), 400
            
            # Register user
            success, message, recovery_token = auth_manager.register_user(username, password, access_key, referral_code)
            
            if success:
                return jsonify({"success": True, "message": "Rejestracja pomyślna! Możesz się teraz zalogować.", "recovery_token": recovery_token})
            else:
                return jsonify({"success": False, "error": message}), 400
                
        except Exception as e:
            logging.error(f"Error in user registration: {e}")
            return jsonify({"success": False, "error": "Wystąpił błąd podczas rejestracji"}), 500
    
    return render_template("register.html",
                           total_registered_users=total_registered_users,
                           num_active_users=num_active_users,
                           top_user=top_user)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute") # Limit login attempts
def login():
    all_users = auth_manager.get_all_users()
    total_registered_users = len(all_users)
    active_users = [user for user in all_users if user.get('is_active') == 1]
    num_active_users = len(active_users)

    top_user = None
    if all_users:
        top_user = max(all_users, key=lambda user: user.get('hubert_coins', 0))

    if request.method == "POST":
        try:
            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "").strip()
            
            app.logger.debug(f"Login attempt for user: '{username}' from IP: {request.remote_addr}")
            
            if not username or not password:
                app.logger.warning(f"Login failed for user '{username}': missing username or password.")
                return jsonify({"success": False, "error": "Nazwa użytkownika i hasło są wymagane"}), 400
            
            # Authenticate user - metoda zwraca tuple (bool, str)
            remember = data.get("remember", False)
            success, message, user = auth_manager.authenticate_user(username, password)
            
            if success and user:
                login_user(user, remember=remember)
                app.logger.info(f"User '{username}' logged in successfully.")
                return jsonify({"success": True, "message": "Logowanie pomyślne"})
            else:
                app.logger.warning(f"Login failed for user '{username}': {message}")
                return jsonify({"success": False, "error": message}), 401
                
        except Exception as e:
            logging.error(f"Error in user login: {e}")
            return jsonify({'success': False, 'error': 'Wystąpił błąd podczas logowania'})
    
    return render_template("login.html",
                           total_registered_users=total_registered_users,
                           num_active_users=num_active_users,
                           top_user=top_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/profile")
@login_required
def profile():
    user_info = auth_manager.get_user_info(current_user.username)
    hubert_coins = user_info.get("hubert_coins", 0) if user_info else 0
    
    return render_template("profile.html", username=current_user.username, hubert_coins=hubert_coins)

@app.route("/logowaniedozmodyfikowanieplikuhtml")
def logowanie_do_modyfikacji():
    return render_template("logowaniedozmodyfikowanieplikuhtml.html")

@app.route("/forgot_password_page")
def forgot_password_page():
    return render_template("forgot_password_page.html")

@app.route("/reset_password_page")
def reset_password_page():
    return render_template("reset_password_page.html")

@app.route("/static/js/<path:filename>")
def serve_js_from_static(filename):
    return send_from_directory(app.static_folder, 'js/' + filename)

@app.route("/user_files/<filename>")
@login_required
def user_files(filename):
    """Serve user files"""
    username = current_user.username
    user_data_dir = "user_data"
    user_folder = os.path.join(user_data_dir, username)
    files_folder = os.path.join(user_folder, "files")
    file_path = os.path.join(files_folder, filename)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return send_file(file_path)
    else:
        # Serve a default image if the user's file is not found
        default_image_path = os.path.join(app.static_folder, 'personicon.svg')
        if os.path.exists(default_image_path):
            return send_from_directory(app.static_folder, 'personicon.svg')
        else:
            return jsonify({"error": "Plik nie został znaleziony i brak domyślnego obrazu"}), 404

@app.route("/api/user", methods=["GET"])
@login_required
def get_user():
    user_info = auth_manager.get_user_info(current_user.username)
    return jsonify(user_info)

@app.route("/api/notifications", methods=["GET"])
@login_required
def get_notifications():
    notifications = auth_manager.get_notifications(current_user.username)
    return jsonify(notifications)

@app.route("/api/notifications/read", methods=["POST"])
@login_required
def mark_notification_as_read():
    data = request.get_json()
    notification_id = data.get("id")
    if notification_id:
        auth_manager.mark_notification_as_read(notification_id)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Brak ID powiadomienia"})

if __name__ == '__main__':
    # Development server configuration
    app.run(debug=True, host='0.0.0.0', port=5001)

