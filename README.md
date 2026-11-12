# Passkey

A small, self-hosted, single-owner password vault. Flask, SQLite, and vanilla HTML/CSS/JavaScript; no frontend build or external assets.

## Run with Docker

```sh
mkdir -p data
PUID=$(id -u) PGID=$(id -g) docker compose up -d --build
```

`PUID` and `PGID` run the container as your host user so the mapped folder is writable on Linux. For subsequent deployments, use the same command or save those numeric IDs as `PUID=...` and `PGID=...` in `.env`. Without overrides, the container uses UID/GID 10001, which requires the folder to be writable by that user.

Open **http://localhost:3100**, then create your master password (at least 12 characters). The first visitor creates the owner: complete setup locally before exposing the service. SQLite is stored at `./data/vault.db` through a bind mount from `./data` to `/app/data`. There is no named Docker volume. Container rebuilds and `docker compose down` leave the host folder intact.

For access beyond localhost, put the app behind an HTTPS reverse proxy and set `COOKIE_SECURE=true` in a `.env` file. Bind the compose port to `127.0.0.1:3100:3100` if the proxy runs on the host. Clipboard access requires HTTPS or localhost in most browsers.

## Features

- Responsive left navigation: Passwords, Authenticator, Password generator, and categories
- Create, edit, permanently delete, search, and sort logins
- Show/hide and copy passwords
- Configurable local password generator using Web Crypto with unbiased sampling
- Encrypted TOTP authenticator keys, live codes, countdowns, and one-click copy
- Account list and detail pane with quick copy actions
- Manual lock and 15-minute inactivity lock
- Encrypted SQLite storage, persistent host folder, container health check

## Security model

The master password is never stored. A fresh 32-byte random salt and scrypt (`N=131072, r=8, p=1`) derive 64 bytes: one half is the constant-time checked authentication verifier, and the other half is the Fernet encryption key. These distinct halves prevent the stored verifier from serving as the encryption key. Fernet provides authenticated encryption with a random IV for each write. Every entry's name, username, password, website, notes, category, and favorite status are encrypted together before SQLite storage. IDs and Fernet timestamps remain visible.

The encryption key exists only in process memory during an unlocked session. An opaque HttpOnly, SameSite=Strict cookie identifies the session; no passwords or keys are stored in localStorage. Sessions expire after 15 minutes without API activity; the UI also clears its plaintext after 15 minutes without interaction. Restarting the service locks all sessions. Keep **one Gunicorn worker** because sessions live in memory; multiple threads are supported. Unlock attempts are limited to five per minute across the instance. Mutations require a custom request header; no cross-origin access is enabled.

This is a personal server-side vault, not an audited zero-knowledge product. The trusted server receives your master password during unlock and decrypted entries are present in browser memory while unlocked. Use HTTPS, a strong unique master password, and a trusted host. There is no password recovery or reset: losing the master password loses access to the vault. Take encrypted database backups and keep the master password separately.

## Back up

For a consistent offline backup, stop the container before copying SQLite (WAL files may exist):

```sh
docker compose stop passkey
cp -a ./data ./vault-backup
docker compose start passkey
```

To restore, stop the service and copy the backed-up directory contents into `./data`, preserving permissions for the configured `PUID`/`PGID`. Use a fresh backup destination each time. Never commit database files or backups to source control.

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

## Moving an existing Docker volume to the host folder

If you previously deployed with the named volume, copy its data **before recreating the container** with the new Compose configuration:

```sh
docker compose stop passkey
docker compose cp passkey:/app/data ./volume-backup
mkdir -p data
cp -a ./volume-backup/. ./data/
PUID=$(id -u) PGID=$(id -g) docker compose up -d --build
```

Use an empty `./data` folder for this migration and a new backup destination. Ensure the copied files are writable by the configured host user. Verify your existing master password unlocks the migrated vault before removing the old volume or backup. The old named volume is not removed by this configuration change.

## Password generator

Choose length (12–64 characters), lowercase, uppercase, numbers, symbols, and optional exclusion of similar-looking characters. Every selected character type appears in the result. Passwords are generated locally using Web Crypto with rejection sampling, then can be copied or inserted into a new account with **Use this password**. At least one character type must remain selected.

## Authenticator (2FA codes)

Open **Authenticator → Add credentials**, or select a saved login and choose **Set up 2FA**. Paste the Base32 setup key or an `otpauth://totp/` setup link from the provider. Use the provider's existing enrollment flow to confirm a generated code before relying on it. An account can contain a password, an authenticator, or both.

Codes follow [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), supporting SHA1/SHA256/SHA512, six or eight digits, and intervals from 15 to 120 seconds. Defaults are SHA1, six digits, and 30 seconds. Setup links supply their own parameters. HOTP and camera/QR scanning are not supported; paste the key or link instead. Keep the server clock synchronized. The display countdown uses server time, and code refreshes do not extend the vault's idle session.

Authenticator secrets are encrypted inside the existing entry payload; existing databases need no schema migration. Locking clears displayed codes and in-memory frontend data. The dedicated code endpoint returns current codes, not setup keys. Secrets are accessible through the unlocked entry editor, just like saved passwords.

This feature generates 2FA codes **for your saved accounts**; it does not add a second factor to unlocking Passkey. Keeping both a password and its authenticator secret in one vault is convenient, but a vault compromise can expose both. Keep recovery codes separately. Removing an authenticator from Passkey does not disable 2FA on the provider's account.

The account list/detail layout and companion tools are inspired by [EasePass](https://github.com/FrozenAssassine/EasePass). The web implementation uses original code and adds no runtime dependencies.

Test the password generator with Node.js 20+:

```sh
node --test tests/test_generator.mjs
```
