import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePassword } from '../static/password-generator.mjs';

test('generated passwords meet every selected character requirement', () => {
  for (let iteration = 0; iteration < 100; iteration++) {
    const password = generatePassword({ length: 32 });
    assert.equal(password.length, 32);
    for (const pattern of [/[a-z]/, /[A-Z]/, /[0-9]/, /[!@#$%^&*()\-_=+\[\]{}?]/]) assert.match(password, pattern);
  }
});
test('character controls, exclusions, and length boundaries', () => {
  assert.match(generatePassword({ length: 12, lowercase: false, uppercase: false, symbols: false }), /^\d{12}$/);
  assert.match(generatePassword({ length: 64, uppercase: false, numbers: false, symbols: false }), /^[a-z]{64}$/);
  for (let i = 0; i < 30; i++) assert.doesNotMatch(generatePassword({ excludeAmbiguous: true }), /[Il1O0|]/);
});
test('invalid or empty generator settings cannot yield a password', () => {
  assert.throws(() => generatePassword({ length: 11 }), RangeError);
  assert.throws(() => generatePassword({ length: 65 }), RangeError);
  assert.throws(() => generatePassword({ length: NaN }), RangeError);
  assert.throws(() => generatePassword({ lowercase: false, uppercase: false, numbers: false, symbols: false }), RangeError);
});
