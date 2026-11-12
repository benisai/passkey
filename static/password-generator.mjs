const SETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}?'
};

export function randomIndex(limit) {
  const bytes = new Uint32Array(1);
  const ceiling = Math.floor(2 ** 32 / limit) * limit;
  do { crypto.getRandomValues(bytes); } while (bytes[0] >= ceiling);
  return bytes[0] % limit;
}

export function generatePassword(options = {}) {
  const { length = 20, lowercase = true, uppercase = true, numbers = true,
    symbols = true, excludeAmbiguous = false } = options;
  if (!Number.isInteger(length) || length < 12 || length > 64) {
    throw new RangeError('Choose a password length between 12 and 64.');
  }
  const selected = { lowercase, uppercase, numbers, symbols };
  const groups = Object.entries(SETS)
    .filter(([name]) => selected[name])
    .map(([, chars]) => excludeAmbiguous ? chars.replace(/[Il1O0|]/g, '') : chars);
  if (!groups.length) throw new RangeError('Select at least one character type.');
  const alphabet = groups.join('');
  // Reject complete candidates that miss a selected set. This samples uniformly
  // among allowed passwords, without bias from inserting required characters.
  let password;
  do {
    password = Array.from({ length }, () => alphabet[randomIndex(alphabet.length)]).join('');
  } while (!groups.every(group => [...password].some(char => group.includes(char))));
  return password;
}
