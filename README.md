# Passkey

A small, self-hosted, single-owner password vault. Flask, SQLite, and vanilla HTML/CSS/JavaScript; no frontend build or external assets.

## Run with Docker

```sh
docker compose up -d --build
```

Open **http://localhost:3100**, then create your master password (at least 12 characters). The first visitor creates the owner: complete setup locally before exposing the service. SQLite persists in the `vault_data` Docker volume through container rebuilds. `docker compose down` keeps the vault; `docker compose down -v` destroys it.

For access beyond localhost, put the app behind an HTTPS reverse proxy and set `COOKIE_SECURE=true` in a `.env` file. Bind the compose port to `127.0.0.1:3100:3100` if the proxy runs on the host. Clipboard access requires HTTPS or localhost in most browsers.

## Features

- Responsive left navigation with categories and favorites
- Create, edit, permanently delete, search, and sort logins
- Show/hide and copy passwords
- Local password generator using Web Crypto with unbiased sampling
- Manual lock and 15-minute inactivity lock
- Encrypted SQLite storage, persistent volume, container health check

## Security model

The master password is never stored. A fresh 32-byte random salt and scrypt (`N=131072, r=8, p=1`) derive 64 bytes: one half is the constant-time checked authentication verifier, and the other half is the Fernet encryption key. These distinct halves prevent the stored verifier from serving as the encryption key. Fernet provides authenticated encryption with a random IV for each write. Every entry's name, username, password, website, notes, category, and favorite status are encrypted together before SQLite storage. IDs and Fernet timestamps remain visible.

The encryption key exists only in process memory during an unlocked session. An opaque HttpOnly, SameSite=Strict cookie identifies the session; no passwords or keys are stored in localStorage. Sessions expire after 15 minutes without API activity; the UI also clears its plaintext after 15 minutes without interaction. Restarting the service locks all sessions. Keep **one Gunicorn worker** because sessions live in memory; multiple threads are supported. Unlock attempts are limited to five per minute across the instance. Mutations require a custom request header; no cross-origin access is enabled.

This is a personal server-side vault, not an audited zero-knowledge product. The trusted server receives your master password during unlock and decrypted entries are present in browser memory while unlocked. Use HTTPS, a strong unique master password, and a trusted host. There is no password recovery or reset: losing the master password loses access to the vault. Take encrypted database backups and keep the master password separately.

## Back up

For a consistent offline backup, stop the container before copying SQLite (WAL files may exist):

```sh
docker compose stop passkey
docker compose cp passkey:/app/data ./vault-backup
docker compose start passkey
```

To restore, stop the service and copy the backed-up directory contents into `/app/data`, preserving ownership for UID 10001. Never commit database files or backups to source control.

## Local development and tests

Python 3.11+ is required.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

```sh
.venv/bin/python -m unittest discover -s tests -v
```

The development server listens on port 3100. Production uses Gunicorn as configured in the Dockerfile. No telemetry, external fonts, or third-party frontend requests.
