"""
Server locale per StockFlow ERP.
Serve i file statici e gestisce il salvataggio delle notizie e autenticazione.
Avviare con: python server.py
"""

import hashlib
import http.server
import json
import os
import secrets
import webbrowser
import socketserver
import urllib.parse
import re
from datetime import datetime, timedelta
from http.cookies import SimpleCookie

PORT = 3003
SITE_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd()
NOTIZIE_PATH = os.path.join(SITE_DIR, "data", "notizie.json")
USERS_PATH = os.path.join(SITE_DIR, "data", "users.json")

SESSION_EXPIRY_HOURS = 8
RUOLI = ['editor', 'admin']

# Sessioni in memoria
sessions = {}  # { token: { username, ruolo, expires } }


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return pw_hash.hex(), salt


def verify_password(password, stored_hash, salt):
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return secrets.compare_digest(pw_hash.hex(), stored_hash)


def load_users():
    if not os.path.exists(USERS_PATH):
        return []
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def find_user(users, username):
    for i, u in enumerate(users):
        if u['username'] == username:
            return i, u
    return -1, None


def init_users():
    if os.path.exists(USERS_PATH):
        return False
    pw_hash, salt = hash_password('admin1')
    users = [{
        'username': 'admin',
        'password_hash': pw_hash,
        'salt': salt,
        'ruolo': 'admin',
        'creato': datetime.now().isoformat(timespec='seconds')
    }]
    save_users(users)
    return True


class SitoHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=SITE_DIR, **kwargs)

    def get_current_user(self):
        cookie_header = self.headers.get('Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get('session_token')
        if not morsel:
            return None
        token = morsel.value
        session = sessions.get(token)
        if not session:
            return None
        if datetime.now() > session['expires']:
            del sessions[token]
            return None
        return {'username': session['username'], 'ruolo': session['ruolo']}

    def require_auth(self, ruolo_minimo=None):
        user = self.get_current_user()
        if not user:
            self.send_error_json(401, "Non autenticato")
            return None
        if ruolo_minimo:
            livello_richiesto = RUOLI.index(ruolo_minimo)
            livello_utente = RUOLI.index(user['ruolo']) if user['ruolo'] in RUOLI else -1
            if livello_utente < livello_richiesto:
                self.send_error_json(403, "Permessi insufficienti")
                return None
        return user

    def send_json_with_cookie(self, data, cookie_str):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", cookie_str)
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        return json.loads(body.decode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/utente-corrente":
            self.handle_utente_corrente()
        elif path == "/api/lista-utenti":
            if not self.require_auth('admin'):
                return
            self.handle_lista_utenti()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/login":
            self.handle_login()
        elif self.path == "/api/logout":
            self.handle_logout()
        elif self.path == "/api/cambia-password":
            if not self.require_auth():
                return
            self.handle_cambia_password()
        elif self.path == "/api/crea-utente":
            if not self.require_auth('admin'):
                return
            self.handle_crea_utente()
        elif self.path == "/api/elimina-utente":
            if not self.require_auth('admin'):
                return
            self.handle_elimina_utente()
        elif self.path == "/api/cambia-ruolo":
            if not self.require_auth('admin'):
                return
            self.handle_cambia_ruolo()
        elif self.path == "/api/salva-notizie":
            if not self.require_auth('editor'):
                return
            self.handle_salva_notizie()
        else:
            self.send_error(404, "Endpoint non trovato")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # --- API: Login ---
    def handle_login(self):
        try:
            data = self.read_json_body()
            username = data.get("username", "").strip().lower()
            password = data.get("password", "")

            if not username or not password:
                self.send_error_json(400, "Username e password obbligatori")
                return

            users = load_users()
            _, user = find_user(users, username)
            if not user or not verify_password(password, user['password_hash'], user['salt']):
                self.send_error_json(401, "Credenziali non valide")
                return

            token = secrets.token_urlsafe(32)
            sessions[token] = {
                'username': user['username'],
                'ruolo': user['ruolo'],
                'expires': datetime.now() + timedelta(hours=SESSION_EXPIRY_HOURS)
            }

            cookie = f"session_token={token}; HttpOnly; SameSite=Strict; Path=/"
            self.send_json_with_cookie({
                "ok": True,
                "username": user['username'],
                "ruolo": user['ruolo']
            }, cookie)
            print(f"[OK] Login: {user['username']} ({user['ruolo']})")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except Exception as e:
            self.send_error_json(500, f"Errore login: {e}")

    # --- API: Logout ---
    def handle_logout(self):
        cookie_header = self.headers.get('Cookie', '')
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get('session_token')
        if morsel and morsel.value in sessions:
            del sessions[morsel.value]

        expire_cookie = "session_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        self.send_json_with_cookie({"ok": True, "messaggio": "Logout effettuato"}, expire_cookie)

    # --- API: Utente corrente ---
    def handle_utente_corrente(self):
        user = self.get_current_user()
        if not user:
            self.send_error_json(401, "Non autenticato")
            return
        self.send_json({"ok": True, "username": user['username'], "ruolo": user['ruolo']})

    # --- API: Lista utenti ---
    def handle_lista_utenti(self):
        users = load_users()
        lista = [{"username": u['username'], "ruolo": u['ruolo'], "creato": u.get('creato', '')} for u in users]
        self.send_json({"ok": True, "utenti": lista})

    # --- API: Crea utente ---
    def handle_crea_utente(self):
        try:
            data = self.read_json_body()
            username = data.get("username", "").strip().lower()
            password = data.get("password", "")
            ruolo = data.get("ruolo", "editor")

            if not re.match(r'^[a-z0-9._-]{3,30}$', username):
                self.send_error_json(400, "Username non valido (3-30 caratteri, solo a-z 0-9 . _ -)")
                return
            if len(password) < 6:
                self.send_error_json(400, "Password troppo corta (minimo 6 caratteri)")
                return
            if ruolo not in RUOLI:
                self.send_error_json(400, f"Ruolo non valido. Ruoli ammessi: {', '.join(RUOLI)}")
                return

            users = load_users()
            _, existing = find_user(users, username)
            if existing:
                self.send_error_json(400, f"Username '{username}' gia' in uso")
                return

            pw_hash, salt = hash_password(password)
            users.append({
                'username': username,
                'password_hash': pw_hash,
                'salt': salt,
                'ruolo': ruolo,
                'creato': datetime.now().isoformat(timespec='seconds')
            })
            save_users(users)
            self.send_json({"ok": True, "messaggio": f"Utente '{username}' creato con ruolo {ruolo}"})
            print(f"[OK] Utente creato: {username} ({ruolo})")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except Exception as e:
            self.send_error_json(500, f"Errore creazione utente: {e}")

    # --- API: Elimina utente ---
    def handle_elimina_utente(self):
        try:
            data = self.read_json_body()
            username = data.get("username", "").strip().lower()
            current_user = self.get_current_user()

            if not username:
                self.send_error_json(400, "Username obbligatorio")
                return
            if username == current_user['username']:
                self.send_error_json(400, "Non puoi eliminare te stesso")
                return

            users = load_users()
            idx, user = find_user(users, username)
            if idx == -1:
                self.send_error_json(404, f"Utente '{username}' non trovato")
                return

            if user['ruolo'] == 'admin':
                admin_count = sum(1 for u in users if u['ruolo'] == 'admin')
                if admin_count <= 1:
                    self.send_error_json(400, "Impossibile eliminare l'ultimo admin")
                    return

            users.pop(idx)
            save_users(users)
            tokens_to_remove = [t for t, s in sessions.items() if s['username'] == username]
            for t in tokens_to_remove:
                del sessions[t]

            self.send_json({"ok": True, "messaggio": f"Utente '{username}' eliminato"})
            print(f"[OK] Utente eliminato: {username}")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except Exception as e:
            self.send_error_json(500, f"Errore eliminazione utente: {e}")

    # --- API: Cambia password ---
    def handle_cambia_password(self):
        try:
            data = self.read_json_body()
            password_attuale = data.get("password_attuale", "")
            password_nuova = data.get("password_nuova", "")
            current_user = self.get_current_user()

            if not password_attuale or not password_nuova:
                self.send_error_json(400, "Password attuale e nuova obbligatorie")
                return
            if len(password_nuova) < 6:
                self.send_error_json(400, "Nuova password troppo corta (minimo 6 caratteri)")
                return

            users = load_users()
            idx, user = find_user(users, current_user['username'])
            if idx == -1:
                self.send_error_json(404, "Utente non trovato")
                return

            if not verify_password(password_attuale, user['password_hash'], user['salt']):
                self.send_error_json(401, "Password attuale non corretta")
                return

            pw_hash, salt = hash_password(password_nuova)
            users[idx]['password_hash'] = pw_hash
            users[idx]['salt'] = salt
            save_users(users)
            self.send_json({"ok": True, "messaggio": "Password cambiata con successo"})
            print(f"[OK] Password cambiata: {current_user['username']}")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except Exception as e:
            self.send_error_json(500, f"Errore cambio password: {e}")

    # --- API: Cambia ruolo ---
    def handle_cambia_ruolo(self):
        try:
            data = self.read_json_body()
            username = data.get("username", "").strip().lower()
            nuovo_ruolo = data.get("ruolo", "")

            if not username or not nuovo_ruolo:
                self.send_error_json(400, "Username e ruolo obbligatori")
                return
            if nuovo_ruolo not in RUOLI:
                self.send_error_json(400, f"Ruolo non valido. Ruoli ammessi: {', '.join(RUOLI)}")
                return

            users = load_users()
            idx, user = find_user(users, username)
            if idx == -1:
                self.send_error_json(404, f"Utente '{username}' non trovato")
                return

            if user['ruolo'] == 'admin' and nuovo_ruolo != 'admin':
                admin_count = sum(1 for u in users if u['ruolo'] == 'admin')
                if admin_count <= 1:
                    self.send_error_json(400, "Impossibile declassare l'ultimo admin")
                    return

            users[idx]['ruolo'] = nuovo_ruolo
            save_users(users)

            for s in sessions.values():
                if s['username'] == username:
                    s['ruolo'] = nuovo_ruolo

            self.send_json({"ok": True, "messaggio": f"Ruolo di '{username}' cambiato in {nuovo_ruolo}"})
            print(f"[OK] Ruolo cambiato: {username} -> {nuovo_ruolo}")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except Exception as e:
            self.send_error_json(500, f"Errore cambio ruolo: {e}")

    # --- API: Salva notizie ---
    def handle_salva_notizie(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            notizie = json.loads(body.decode("utf-8"))

            if not isinstance(notizie, list):
                raise ValueError("Il formato deve essere una lista di notizie")

            for i, n in enumerate(notizie):
                if not n.get("titolo") or not n.get("categoria"):
                    raise ValueError(f"Notizia {i+1}: titolo e categoria sono obbligatori")

            if os.path.exists(NOTIZIE_PATH):
                backup = NOTIZIE_PATH + ".backup"
                with open(NOTIZIE_PATH, "r", encoding="utf-8") as f:
                    with open(backup, "w", encoding="utf-8") as fb:
                        fb.write(f.read())

            os.makedirs(os.path.dirname(NOTIZIE_PATH), exist_ok=True)
            with open(NOTIZIE_PATH, "w", encoding="utf-8") as f:
                json.dump(notizie, f, ensure_ascii=False, indent=2)

            self.send_json({"ok": True, "messaggio": f"Salvate {len(notizie)} notizie"})
            print(f"[OK] Salvate {len(notizie)} notizie in {NOTIZIE_PATH}")

        except json.JSONDecodeError:
            self.send_error_json(400, "JSON non valido")
        except ValueError as e:
            self.send_error_json(400, str(e))
        except Exception as e:
            self.send_error_json(500, f"Errore interno: {e}")

    # --- Utility ---
    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def send_error_json(self, code, messaggio):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        resp = {"ok": False, "errore": messaggio}
        self.wfile.write(json.dumps(resp).encode("utf-8"))
        print(f"[ERRORE] {messaggio}")

    def log_message(self, format, *args):
        msg = format % args
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"  [{timestamp}] {msg}")


def main():
    created = init_users()
    with socketserver.TCPServer(("", PORT), SitoHandler) as httpd:
        url = f"http://localhost:{PORT}"
        print("=" * 50)
        print("  StockFlow ERP")
        print("  Server locale avviato")
        print(f"  Sito:    {url}")
        print(f"  Admin:   {url}/admin.html")
        print("=" * 50)
        if created:
            print("  ** Account admin creato con password predefinita **")
            print("  ** Username: admin / Password: admin1           **")
            print("  ** Cambiare la password al primo accesso!       **")
            print("=" * 50)
        print("  Premi Ctrl+C per chiudere il server")
        print()

        webbrowser.open(f"{url}/admin.html")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer chiuso.")


if __name__ == "__main__":
    main()
