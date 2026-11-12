"""Single-owner encrypted vault. Run with one worker: keys live only in memory."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, abort, g, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from totp import generate_totp, normalize_totp

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
DB_PATH = os.environ.get('DATABASE_PATH', 'data/vault.db')
SESSION_SECONDS = 15 * 60
sessions = {}
attempts = []
lock = threading.RLock()


def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    connection = g.pop('db', None)
    if connection:
        connection.close()


def initialize():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as connection:
        connection.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS owner (
              id INTEGER PRIMARY KEY CHECK (id = 1),
              salt BLOB NOT NULL, verifier BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS entries (
              id TEXT PRIMARY KEY, payload BLOB NOT NULL);
        ''')
    os.chmod(DB_PATH, 0o600)


def derive(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**17, r=8, p=1,
                          dklen=64, maxmem=256 * 1024 * 1024)


def body():
    if not request.is_json:
        abort(415, 'JSON is required.')
    value = request.get_json()
    if not isinstance(value, dict):
        abort(400, 'Expected a JSON object.')
    return value


@app.before_request
def protect():
    if request.path.startswith('/api/'):
        if request.method != 'GET' and request.headers.get('X-Vault-Request') != '1':
            abort(403, 'Missing request protection header.')
        now = time.monotonic()
        with lock:
            for token in list(sessions):
                if sessions[token]['expires'] < now:
                    del sessions[token]
            session = sessions.get(request.cookies.get('vault_session'))
            if session:
                # Automatic code refresh must not keep an unattended vault unlocked.
                if request.path != '/api/totp':
                    session['expires'] = now + SESSION_SECONDS
                g.cipher = session['cipher']
        if request.path not in ('/api/status', '/api/setup', '/api/unlock', '/api/lock') and not session:
            abort(401, 'Your vault is locked. Unlock it to continue.')


@app.after_request
def headers(response):
    if hasattr(g, 'cipher') and request.path not in ('/api/lock', '/api/totp') and 'Set-Cookie' not in response.headers:
        response.set_cookie('vault_session', request.cookies['vault_session'],
                            httponly=True, samesite='Strict',
                            secure=os.environ.get('COOKIE_SECURE', 'false').lower() == 'true',
                            max_age=SESSION_SECONDS, path='/')
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


@app.errorhandler(HTTPException)
def http_error(error):
    return jsonify(error=error.description), error.code


def authenticated(material):
    token = secrets.token_urlsafe(32)
    with lock:
        sessions.pop(request.cookies.get('vault_session'), None)
        sessions[token] = dict(cipher=Fernet(base64.urlsafe_b64encode(material[32:])),
                               expires=time.monotonic() + SESSION_SECONDS)
    response = jsonify(ok=True)
    response.set_cookie('vault_session', token, httponly=True, samesite='Strict',
                        secure=os.environ.get('COOKIE_SECURE', 'false').lower() == 'true',
                        max_age=SESSION_SECONDS, path='/')
    return response


@app.get('/')
def index():
    return send_from_directory('static', 'index.html')


@app.get('/health')
def health():
    db().execute('SELECT 1')
    return jsonify(ok=True)


@app.get('/api/status')
def status():
    return jsonify(initialized=db().execute('SELECT 1 FROM owner').fetchone() is not None,
                   unlocked=hasattr(g, 'cipher'))


@app.post('/api/setup')
def setup():
    password = body().get('password')
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        abort(400, 'Use a master password between 12 and 1,024 characters.')
    # Serialize the first-owner transaction and expensive KDF within this process.
    with lock:
        if db().execute('SELECT 1 FROM owner').fetchone():
            abort(409, 'This vault is already set up.')
        salt = secrets.token_bytes(32)
        material = derive(password, salt)
        try:
            db().execute('INSERT INTO owner VALUES (1, ?, ?)', (salt, material[:32]))
            db().commit()
        except sqlite3.IntegrityError:
            abort(409, 'This vault is already set up.')
    return authenticated(material)


@app.post('/api/unlock')
def unlock():
    password = body().get('password')
    if not isinstance(password, str) or len(password) > 1024:
        abort(400, 'Invalid password.')
    with lock:
        now = time.monotonic()
        attempts[:] = [t for t in attempts if now - t < 60]
        if len(attempts) >= 5:
            abort(429, 'Too many unlock attempts. Wait one minute and try again.')
        attempts.append(now)
        owner = db().execute('SELECT * FROM owner').fetchone()
        if not owner:
            abort(409, 'Create your vault first.')
        material = derive(password, owner['salt'])
        if not hmac.compare_digest(material[:32], owner['verifier']):
            abort(401, 'Incorrect master password.')
    return authenticated(material)


@app.post('/api/lock')
def lock_vault():
    with lock:
        sessions.pop(request.cookies.get('vault_session'), None)
    response = jsonify(ok=True)
    response.delete_cookie('vault_session', path='/')
    return response


def decrypt(row):
    try:
        data = json.loads(g.cipher.decrypt(row['payload']))
    except (InvalidToken, ValueError):
        abort(500, 'An entry could not be decrypted. Restore a known-good backup.')
    return dict(data, id=row['id'], totp=data.get('totp'))


@app.get('/api/entries')
def entries():
    return jsonify([decrypt(row) for row in db().execute('SELECT * FROM entries')])


@app.get('/api/totp')
def authenticator_codes():
    now = time.time()
    codes = []
    for row in db().execute('SELECT * FROM entries'):
        entry = decrypt(row)
        if entry['totp']:
            codes.append(dict(id=entry['id'], **generate_totp(entry['totp'], now)))
    return jsonify(server_time=now, codes=codes)


def entry_data():
    data = body()
    result = {}
    for field, limit in [('name', 100), ('username', 320), ('password', 4096), ('url', 2048), ('notes', 10000), ('category', 30)]:
        value = data.get(field, '')
        if not isinstance(value, str) or len(value) > limit:
            abort(400, f'Invalid {field}.')
        result[field] = value if field == 'password' else value.strip()
    try:
        result['totp'] = normalize_totp(data.get('totp'))
    except ValueError as error:
        abort(400, str(error))
    if not result['name'] or not (result['password'] or result['totp']):
        abort(400, 'A name and either a password or an authenticator setup key are required.')
    if result['category'] not in ('Personal', 'Work', 'Finance', 'Social', 'Other'):
        abort(400, 'Choose a valid category.')
    if result['url']:
        try:
            parsed = urlsplit(result['url'])
            if parsed.scheme not in ('https', 'http') or not parsed.hostname or any(c.isspace() for c in result['url']) or '\\' in result['url']:
                raise ValueError()
            parsed.port  # Validate malformed port numbers, too.
        except ValueError:
            abort(400, 'Enter a valid website starting with https:// or http://.')
    result['favorite'] = data.get('favorite') is True
    result['updated'] = int(time.time())
    return result


@app.post('/api/entries')
def create_entry():
    data = entry_data()
    identifier = secrets.token_hex(16)
    payload = g.cipher.encrypt(json.dumps(data).encode())
    db().execute('INSERT INTO entries VALUES (?, ?)', (identifier, payload))
    db().commit()
    return jsonify(dict(data, id=identifier)), 201


@app.put('/api/entries/<identifier>')
def update_entry(identifier):
    data = entry_data()
    cursor = db().execute('UPDATE entries SET payload=? WHERE id=?',
                          (g.cipher.encrypt(json.dumps(data).encode()), identifier))
    if not cursor.rowcount:
        abort(404, 'Entry not found.')
    db().commit()
    return jsonify(dict(data, id=identifier))


@app.delete('/api/entries/<identifier>')
def delete_entry(identifier):
    cursor = db().execute('DELETE FROM entries WHERE id=?', (identifier,))
    if not cursor.rowcount:
        abort(404, 'Entry not found.')
    db().commit()
    return jsonify(ok=True)


initialize()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=3100)
