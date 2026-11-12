import importlib
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path


class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        os.environ['DATABASE_PATH'] = str(Path(cls.temp.name) / 'vault.db')
        cls.module = importlib.import_module('app')
        cls.module.app.config['TESTING'] = True

    def setUp(self):
        self.client = self.module.app.test_client()
        self.module.sessions.clear()
        self.module.attempts.clear()
        with sqlite3.connect(self.module.DB_PATH) as db:
            db.execute('DELETE FROM entries')
            db.execute('DELETE FROM owner')
        self.headers = {'X-Vault-Request': '1'}
        self.password = 'a strong unique master password!'

    def post(self, path, data=None):
        return self.client.post('/api/' + path, json=data or {}, headers=self.headers)

    def setup(self):
        self.assertEqual(self.post('setup', {'password': self.password}).status_code, 200)

    def test_lifecycle_and_encryption(self):
        self.assertEqual(self.client.get('/api/entries').status_code, 401)
        self.setup()
        self.assertEqual(self.post('setup', {'password': self.password}).status_code, 409)
        entry = dict(name='Private bank', username='private@example.com', password='S3cret-vault-value!', url='https://example.com', notes='secret notes', category='Finance', favorite=True)
        response = self.post('entries', entry)
        self.assertEqual(response.status_code, 201)
        identifier = response.json['id']
        with sqlite3.connect(self.module.DB_PATH) as db:
            encrypted = db.execute('SELECT payload FROM entries').fetchone()[0]
            salt, verifier = db.execute('SELECT salt, verifier FROM owner').fetchone()
        for value in [entry['name'], entry['username'], entry['password'], entry['notes']]:
            self.assertNotIn(value.encode(), encrypted)
        self.assertEqual(len(salt), 32)
        self.assertNotEqual(verifier, self.password.encode())
        self.assertEqual(self.client.get('/api/entries').json[0]['password'], entry['password'])
        self.post('lock')
        self.assertEqual(self.client.get('/api/entries').status_code, 401)
        self.assertEqual(self.post('unlock', {'password': 'incorrect'}).status_code, 401)
        self.assertEqual(self.post('unlock', {'password': self.password}).status_code, 200)
        entry['name'] = 'Updated bank'
        result = self.client.put('/api/entries/' + identifier, json=entry, headers=self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.client.get('/api/entries').json[0]['name'], 'Updated bank')
        self.assertEqual(self.client.delete('/api/entries/' + identifier, headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get('/api/entries').json, [])
        self.assertEqual(self.client.delete('/api/entries/' + identifier, headers=self.headers).status_code, 404)

    def test_validation_csrf_and_headers(self):
        self.assertEqual(self.client.post('/api/setup', json={'password': self.password}).status_code, 403)
        self.assertEqual(self.post('setup', {'password': 'short'}).status_code, 400)
        self.setup()
        entry = dict(name='Test', password='password', category='Personal', url='javascript:alert(1)')
        self.assertEqual(self.post('entries', entry).status_code, 400)
        for url in ['http://', 'https://[invalid', 'https://example.com:bad', 'http://bad host']:
            entry['url'] = url
            self.assertEqual(self.post('entries', entry).status_code, 400)
        entry['url'] = 'https://example.com'
        entry['name'] = 'x' * 101
        self.assertEqual(self.post('entries', entry).status_code, 400)
        self.assertEqual(self.client.post('/api/entries', json=[], headers=self.headers).status_code, 400)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        response.close()

    def test_expiry_and_rate_limit(self):
        self.setup()
        for session in self.module.sessions.values():
            session['expires'] = time.monotonic() - 1
        self.assertEqual(self.client.get('/api/entries').status_code, 401)
        self.assertEqual(len(self.module.sessions), 0)
        for _ in range(5):
            self.assertEqual(self.post('unlock', {'password': 'wrong'}).status_code, 401)
        self.assertEqual(self.post('unlock', {'password': self.password}).status_code, 429)

    def test_cookie_and_session_isolation(self):
        response = self.post('setup', {'password': self.password})
        self.assertIn('HttpOnly', response.headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', response.headers['Set-Cookie'])
        # Reauthentication must preserve the newly rotated session cookie.
        self.assertEqual(self.post('unlock', {'password': self.password}).status_code, 200)
        self.assertEqual(self.client.get('/api/entries').status_code, 200)
        stranger = self.module.app.test_client()
        self.assertEqual(stranger.get('/api/entries').status_code, 401)
        self.module.sessions.clear()
        self.assertEqual(self.client.get('/api/entries').status_code, 401)


if __name__ == '__main__':
    unittest.main()
