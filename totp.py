"""TOTP provisioning and RFC 6238 codes using only the Python standard library."""
import base64
import binascii
import hashlib
import hmac
import re
from urllib.parse import parse_qs, urlsplit

ALGORITHMS = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


def normalize_totp(value):
    """Return validated, canonical configuration or None for an empty field."""
    if value is None or value == '':
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if len(text) > 4096:
            raise ValueError('The authenticator setup key is too long.')
        if text.lower().startswith('otpauth:'):
            uri = urlsplit(text)
            if uri.scheme != 'otpauth' or uri.netloc != 'totp':
                raise ValueError('Use a time-based otpauth://totp/ setup link. HOTP is not supported.')
            params = parse_qs(uri.query, keep_blank_values=True)
            if any(len(values) != 1 for values in params.values()):
                raise ValueError('The authenticator link contains duplicate parameters.')
            data = {key: values[0] for key, values in params.items()}
        else:
            data = {'secret': text}
    elif isinstance(value, dict):
        data = value
    else:
        raise ValueError('Enter a Base32 setup key or an otpauth://totp/ link.')
    secret = data.get('secret', '')
    if not isinstance(secret, str) or len(secret) > 4096:
        raise ValueError('Invalid authenticator setup key.')
    secret = re.sub(r'[\s-]', '', secret).upper().rstrip('=')
    if not re.fullmatch(r'[A-Z2-7]+', secret):
        raise ValueError('Enter a valid Base32 setup key (letters A–Z and digits 2–7).')
    try:
        decoded = base64.b32decode(secret + '=' * (-len(secret) % 8))
    except (binascii.Error, ValueError) as error:
        raise ValueError('The Base32 setup key has an invalid length.') from error
    if not 10 <= len(decoded) <= 128 or base64.b32encode(decoded).decode().rstrip('=') != secret:
        raise ValueError('Use a valid setup key containing between 10 and 128 decoded bytes.')
    algorithm = data.get('algorithm', 'SHA1')
    if not isinstance(algorithm, str) or algorithm.upper() not in ALGORITHMS:
        raise ValueError('Authenticator algorithm must be SHA1, SHA256, or SHA512.')
    digits = data.get('digits', 6)
    period = data.get('period', 30)
    if type(digits) not in (int, str) or str(digits) not in ('6', '8'):
        raise ValueError('Authenticator codes must contain 6 or 8 digits.')
    if type(period) not in (int, str) or not re.fullmatch(r'\d{1,3}', str(period)) or not 15 <= int(period) <= 120:
        raise ValueError('Authenticator refresh interval must be 15–120 seconds.')
    return dict(secret=secret, algorithm=algorithm.upper(), digits=int(digits), period=int(period))


def generate_totp(config, timestamp):
    secret = config['secret']
    key = base64.b32decode(secret + '=' * (-len(secret) % 8))
    counter = int(timestamp) // config['period']
    digest = hmac.new(key, counter.to_bytes(8, 'big'), ALGORITHMS[config['algorithm']]).digest()
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff
    code = str(number % (10 ** config['digits'])).zfill(config['digits'])
    return dict(code=code, period=config['period'], valid_until=(counter + 1) * config['period'])
