import base64
import unittest

from totp import generate_totp, normalize_totp


class TOTPTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        # Appendix B: all six times for each supported hash, including >32-bit time.
        times = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        expected = {
            'SHA1': ['94287082', '07081804', '14050471', '89005924', '69279037', '65353130'],
            'SHA256': ['46119246', '68084774', '67062674', '91819424', '90698825', '77737706'],
            'SHA512': ['90693936', '25091201', '99943326', '93441116', '38618901', '47863826'],
        }
        for algorithm, size in [('SHA1', 20), ('SHA256', 32), ('SHA512', 64)]:
            secret = base64.b32encode((b'1234567890' * 7)[:size]).decode().rstrip('=')
            config = normalize_totp(dict(secret=secret, digits=8, algorithm=algorithm))
            for timestamp, code in zip(times, expected[algorithm]):
                with self.subTest(algorithm=algorithm, timestamp=timestamp):
                    result = generate_totp(config, timestamp)
                    self.assertEqual(result['code'], code)
                    self.assertEqual(result['valid_until'], (timestamp // 30 + 1) * 30)

    def test_setup_keys_and_uris(self):
        config = normalize_totp('jbsw y3dp-ehpk3pxp')
        self.assertEqual(config, dict(secret='JBSWY3DPEHPK3PXP', algorithm='SHA1', digits=6, period=30))
        uri = 'otpauth://totp/Example:you?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60'
        self.assertEqual(normalize_totp(uri), dict(secret=config['secret'], algorithm='SHA256', digits=8, period=60))
        self.assertEqual(generate_totp(config, 29)['valid_until'], 30)
        self.assertEqual(generate_totp(config, 30)['valid_until'], 60)
        self.assertNotEqual(generate_totp(config, 29)['code'], generate_totp(config, 30)['code'])

    def test_invalid_configuration(self):
        for value in [123, [], '12345', 'ABC', 'otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP',
                      'otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP',
                      'otpauth://totp/test?secret=', 'A' * 5000,
                      {'secret': 'JBSWY3DPEHPK3PXP', 'algorithm': 'MD5'},
                      {'secret': 'JBSWY3DPEHPK3PXP', 'digits': True},
                      {'secret': 'JBSWY3DPEHPK3PXP', 'period': 30.5},
                      {'secret': 'JBSWY3DPEHPK3PXP', 'period': 0}]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_totp(value)
        self.assertIsNone(normalize_totp(None))
        self.assertIsNone(normalize_totp('  '))
