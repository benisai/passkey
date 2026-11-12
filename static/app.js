'use strict';
import { generatePassword } from './password-generator.mjs';

const $ = id => document.getElementById(id);
let entries = [], view = 'all', initialized = false, selectedId = null;
let lastActivity = Date.now(), toastTimer, codeCache = new Map(), serverOffset = 0;
let refreshingCodes = false, retryCodesAt = 0, authEpoch = 0;

async function api(path, method = 'GET', data) {
  const response = await fetch(`/api/${path}`, {
    method, headers: { 'Content-Type': 'application/json', 'X-Vault-Request': '1' },
    ...(data === undefined ? {} : { body: JSON.stringify(data) })
  });
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== 'unlock') showAuth();
    throw new Error(result.error || 'Something went wrong. Please try again.');
  }
  return result;
}
function toast(message) {
  $('toast').textContent = message; $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3000);
}
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function selectedEntry() { return entries.find(entry => entry.id === selectedId); }
function showAuth() {
  authEpoch++; entries = []; selectedId = null; codeCache.clear(); retryCodesAt = 0;
  $('entries').replaceChildren(); $('authenticator-list').replaceChildren();
  $('entry-form').reset(); $('generated').textContent = ''; $('search').value = '';
  $('detail-content').hidden = true; $('detail-password').value = ''; $('detail-username').value = '';
  for (const id of ['detail-name', 'detail-notes', 'detail-url']) $(id).textContent = '';
  $('detail-url').removeAttribute('href');
  document.querySelectorAll('.totp-code').forEach(node => { node.textContent = '••• •••'; });
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  $('vault').hidden = true; $('auth').hidden = false;
  $('master').value = ''; $('confirm-master').value = ''; $('master').type = 'password';
  $('toggle-master').textContent = 'Show';
  $('auth-title').textContent = initialized ? 'Welcome home.' : 'A safer place to start.';
  $('auth-description').textContent = initialized ? 'Unlock your vault to pick up where you left off.' : 'Create a master password to make this vault yours.';
  $('auth-submit').textContent = initialized ? 'Unlock vault ↗' : 'Create your vault ↗';
  $('confirm-wrap').hidden = initialized; $('confirm-master').required = !initialized;
  $('master').minLength = initialized ? 1 : 12;
  $('master').autocomplete = initialized ? 'current-password' : 'new-password';
  $('auth-note').textContent = initialized ? 'Your vault locks automatically after 15 minutes of inactivity.' : 'Use at least 12 characters. Keep it safe: your master password cannot be recovered.';
  $('master').focus();
}
async function loadVault() {
  entries = await api('entries'); initialized = true; lastActivity = Date.now();
  $('auth').hidden = true; $('vault').hidden = false; $('auth-error').textContent = '';
  $('master').value = ''; $('confirm-master').value = ''; render();
}
function filteredEntries() {
  const query = $('search').value.toLowerCase();
  return entries.filter(entry => (
    view === 'all' || (view === 'favorites' ? entry.favorite : view === 'authenticator' ? entry.totp : entry.category === view)
  ) && [entry.name, entry.username, entry.url, entry.category].some(value => (value || '').toLowerCase().includes(query)))
    .sort($('sort').value === 'updated' ? (a, b) => b.updated - a.updated : (a, b) => a.name.localeCompare(b.name));
}
function selectEntry(entry) {
  selectedId = entry.id; render();
  if (window.matchMedia('(max-width: 1050px)').matches) $('detail-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function nameButton(entry) {
  const button = element('button', 'entry-name'); button.type = 'button';
  button.title = `View ${entry.name}`;
  button.setAttribute('aria-pressed', String(selectedId === entry.id));
  button.append(element('span', 'entry-avatar', entry.name.charAt(0).toUpperCase()));
  let hostname = entry.totp && !entry.password ? 'Authenticator' : 'Password';
  try { if (entry.url) hostname = new URL(entry.url).hostname; } catch { hostname = entry.url; }
  const info = element('div');
  info.append(element('strong', '', entry.name), element('small', '', hostname)); button.append(info);
  button.onclick = () => selectEntry(entry); return button;
}
function passwordRow(entry) {
  const row = element('div', `entry-row${entry.id === selectedId ? ' selected' : ''}`);
  const actions = element('div', 'row-actions');
  const star = element('button', `icon-button${entry.favorite ? ' is-favorite' : ''}`, entry.favorite ? '★' : '☆');
  star.type = 'button'; star.setAttribute('aria-label', `${entry.favorite ? 'Unfavorite' : 'Favorite'} ${entry.name}`);
  star.setAttribute('aria-pressed', String(entry.favorite));
  star.onclick = async () => {
    try {
      const updated = await api(`entries/${entry.id}`, 'PUT', { ...entry, favorite: !entry.favorite });
      entries = entries.map(item => item.id === entry.id ? updated : item); render();
    } catch (error) { toast(error.message); }
  };
  const copy = element('button', 'icon-button', '⧉'); copy.type = 'button';
  copy.setAttribute('aria-label', `Copy ${entry.password ? 'password' : 'authenticator code'} for ${entry.name}`);
  copy.onclick = () => entry.password ? copyText(entry.password) : copyCode(entry.id);
  actions.append(star, copy);
  row.append(nameButton(entry), element('span', 'entry-username', entry.username || '—'), element('span', 'category-pill', entry.category), actions);
  if (entry.totp) row.classList.add('has-authenticator');
  return row;
}
function authenticatorCard(entry) {
  const card = element('div', `authenticator-card${entry.id === selectedId ? ' selected' : ''}`);
  card.dataset.totpId = entry.id;
  const heading = element('div', 'authenticator-card-heading');
  const copy = element('button', 'icon-button', '⧉'); copy.type = 'button';
  copy.setAttribute('aria-label', `Copy authenticator code for ${entry.name}`); copy.onclick = () => copyCode(entry.id);
  heading.append(nameButton(entry), copy);
  const code = element('output', 'totp-code', '••• •••'); code.setAttribute('aria-label', `Code for ${entry.name}`);
  const meta = element('div', 'totp-heading'); meta.append(element('span', '', entry.username || entry.category), element('span', 'totp-remaining', 'Refreshing…'));
  const progress = element('progress', 'totp-progress'); progress.max = entry.totp.period; progress.value = 0; progress.setAttribute('aria-label', `Code time remaining for ${entry.name}`);
  card.append(heading, code, meta, progress); return card;
}
function render() {
  const favorites = entries.filter(entry => entry.favorite).length;
  $('total-stat').textContent = $('all-count').textContent = entries.length;
  $('favorite-stat').textContent = $('fav-count').textContent = favorites;
  $('totp-count').textContent = entries.filter(entry => entry.totp).length;
  document.querySelectorAll('[data-view]').forEach(button => button.classList.toggle('active', button.dataset.view === view));
  const title = { all: 'All passwords', favorites: 'Favorites', generator: 'Password generator', authenticator: 'Authenticator' }[view] || view;
  $('page-title').replaceChildren(document.createTextNode(title), element('span', '', '.'));
  $('breadcrumb').textContent = title;
  $('page-description').textContent = view === 'generator' ? 'Strong passwords, without the guesswork.' : view === 'authenticator' ? 'Your sign-in codes, right where you need them.' : view === 'favorites' ? 'Your everyday essentials, a little closer.' : 'Everything you need, safely in one place.';
  $('vault-content').hidden = view === 'generator'; $('generator').hidden = view !== 'generator';
  $('add').textContent = view === 'authenticator' ? '＋ Add authenticator' : '＋ Add password';
  if (view === 'generator') { if (!$('generated').textContent) generate(); return; }
  const filtered = filteredEntries();
  if (!filtered.some(entry => entry.id === selectedId)) selectedId = filtered[0]?.id || null;
  $('entries').replaceChildren(); $('authenticator-list').replaceChildren();
  $('entries').hidden = view === 'authenticator'; $('table-heading').hidden = view === 'authenticator';
  $('authenticator-list').hidden = view !== 'authenticator';
  filtered.forEach(entry => { $(view === 'authenticator' ? 'authenticator-list' : 'entries').append(view === 'authenticator' ? authenticatorCard(entry) : passwordRow(entry)); });
  $('empty').hidden = filtered.length > 0;
  $('empty').querySelector('h2').textContent = view === 'authenticator' ? 'Your codes. All together.' : entries.length ? 'Nothing here just yet.' : 'A fresh start for your passwords.';
  $('empty').querySelector('p').textContent = view === 'authenticator' ? 'Add an account’s setup key to start generating sign-in codes.' : entries.length ? 'Try another search, or add a password to this collection.' : 'Add your first login. We’ll keep it safe and easy to find.';
  $('empty-add').textContent = view === 'authenticator' ? '＋ Add authenticator' : '＋ Add password';
  $('results').textContent = `${filtered.length} ${view === 'authenticator' ? 'authenticator' : 'account'}${filtered.length === 1 ? '' : 's'}`;
  renderDetail(); tickCodes();
}
function renderDetail() {
  const entry = selectedEntry();
  $('detail-empty').hidden = Boolean(entry); $('detail-content').hidden = !entry;
  // Always discard any previously revealed plaintext when changing selection.
  $('detail-password').type = 'password'; $('detail-password').value = ''; $('reveal-detail').textContent = 'Show';
  if (!entry) return;
  $('detail-name').textContent = entry.name; $('detail-category').textContent = entry.category;
  $('detail-username').value = entry.username || '—'; $('copy-username').disabled = !entry.username;
  $('detail-password-wrap').hidden = !entry.password; $('detail-password').value = entry.password;
  $('detail-totp').hidden = !entry.totp; $('detail-totp').dataset.totpId = entry.id;
  $('add-detail-totp').hidden = Boolean(entry.totp);
  $('detail-url-wrap').hidden = !entry.url; $('detail-url').textContent = entry.url; $('detail-url').href = entry.url || '#';
  $('detail-notes-wrap').hidden = !entry.notes; $('detail-notes').textContent = entry.notes;
  $('detail-updated').textContent = `Updated ${new Date(entry.updated * 1000).toLocaleDateString()}`;
}
function edit(entry, focusAuthenticator = false) {
  $('entry-form').reset(); $('entry-error').textContent = ''; $('entry-id').value = entry?.id || '';
  $('dialog-title').textContent = entry ? 'Edit account' : focusAuthenticator ? 'Add an authenticator' : 'Add a password';
  for (const key of ['name', 'username', 'password', 'url', 'notes', 'category']) {
    $(key).value = entry?.[key] || (key === 'category' ? (['Personal', 'Work', 'Finance', 'Social', 'Other'].includes(view) ? view : 'Personal') : '');
  }
  $('favorite').checked = entry?.favorite || false;
  $('password').type = 'password'; $('toggle-password').textContent = 'Show';
  $('totp-secret').value = entry?.totp?.secret || ''; $('totp-secret').type = 'password'; $('toggle-totp').textContent = 'Show';
  $('totp-algorithm').value = entry?.totp?.algorithm || 'SHA1'; $('totp-digits').value = entry?.totp?.digits || 6;
  $('totp-period').value = entry?.totp?.period || 30;
  $('totp-settings').open = focusAuthenticator || Boolean(entry?.totp);
  $('delete').hidden = !entry; $('entry-dialog').showModal();
  if (focusAuthenticator && entry) $('totp-secret').focus();
}
function generatorOptions() {
  return {
    length: Number($('length').value), lowercase: $('lowercase').checked, uppercase: $('uppercase').checked,
    numbers: $('numbers').checked, symbols: $('symbols').checked, excludeAmbiguous: $('exclude-ambiguous').checked
  };
}
function generate() {
  $('length-value').textContent = $('length').value; $('generator-error').textContent = '';
  try {
    $('generated').textContent = generatePassword(generatorOptions());
    $('copy-generated').disabled = false; $('use-generated').disabled = false;
  } catch (error) {
    $('generated').textContent = ''; $('generator-error').textContent = error.message;
    $('copy-generated').disabled = true; $('use-generated').disabled = true;
  }
}
async function copyText(value) {
  try { await navigator.clipboard.writeText(value); toast('Copied to clipboard.'); }
  catch { toast('Clipboard unavailable. Select and copy the visible value manually.'); }
}
function codesVisible() {
  return !$('vault').hidden && !document.hidden && view !== 'generator' &&
    (view === 'authenticator' ? filteredEntries().some(entry => entry.totp) : Boolean(selectedEntry()?.totp));
}
async function refreshCodes(manual = false) {
  if (refreshingCodes || $('vault').hidden || (!manual && !codesVisible()) || Date.now() < retryCodesAt) return;
  refreshingCodes = true; const epoch = authEpoch;
  try {
    const result = await api('totp');
    if (epoch !== authEpoch || $('vault').hidden) return;
    serverOffset = result.server_time * 1000 - Date.now();
    codeCache = new Map(result.codes.map(code => [code.id, code])); retryCodesAt = 0;
  } catch (error) {
    retryCodesAt = Date.now() + 10000;
    if (!$('vault').hidden) toast(error.message);
  } finally { refreshingCodes = false; }
}
function tickCodes() {
  if (!codesVisible()) return;
  const now = (Date.now() + serverOffset) / 1000;
  let expired = false;
  document.querySelectorAll('[data-totp-id]').forEach(panel => {
    if (panel.hidden) return;
    const code = codeCache.get(panel.dataset.totpId);
    const remaining = code ? Math.max(0, Math.ceil(code.valid_until - now)) : 0;
    panel.querySelector('.totp-code').textContent = remaining ? code.code.slice(0, code.code.length / 2) + ' ' + code.code.slice(code.code.length / 2) : '••• •••';
    panel.querySelector('.totp-remaining').textContent = remaining ? `${remaining}s` : 'Refreshing…';
    const progress = panel.querySelector('progress'); progress.max = code?.period || 30; progress.value = remaining;
    if (!remaining) expired = true;
  });
  if (expired) refreshCodes();
}
async function copyCode(identifier) {
  let code = codeCache.get(identifier);
  if (!code || code.valid_until <= (Date.now() + serverOffset) / 1000) {
    await refreshCodes(true); code = codeCache.get(identifier);
  }
  if ($('vault').hidden) return;
  if (!code || code.valid_until <= (Date.now() + serverOffset) / 1000) { toast('Code unavailable. Please try again.'); return; }
  await copyText(code.code);
}
function toggle(input, button) {
  const hidden = $(input).type === 'password'; $(input).type = hidden ? 'text' : 'password'; $(button).textContent = hidden ? 'Hide' : 'Show';
}
$('auth-form').onsubmit = async event => {
  event.preventDefault(); $('auth-error').textContent = '';
  if (!initialized && $('master').value !== $('confirm-master').value) { $('auth-error').textContent = 'Your passwords do not match.'; return; }
  $('auth-submit').disabled = true;
  try { await api(initialized ? 'unlock' : 'setup', 'POST', { password: $('master').value }); await loadVault(); }
  catch (error) { $('auth-error').textContent = error.message; }
  finally { $('auth-submit').disabled = false; }
};
$('toggle-master').onclick = () => toggle('master', 'toggle-master');
$('toggle-password').onclick = () => toggle('password', 'toggle-password');
$('toggle-totp').onclick = () => toggle('totp-secret', 'toggle-totp');
$('reveal-detail').onclick = () => toggle('detail-password', 'reveal-detail');
$('copy-username').onclick = () => copyText(selectedEntry()?.username || '');
$('copy-detail-password').onclick = () => copyText(selectedEntry()?.password || '');
$('copy-detail-totp').onclick = () => copyCode(selectedId);
$('edit-detail').onclick = () => edit(selectedEntry());
$('add-detail-totp').onclick = () => edit(selectedEntry(), true);
$('delete-detail').onclick = () => { edit(selectedEntry()); $('delete-dialog').showModal(); };
$('lock').onclick = async () => { showAuth(); try { await api('lock', 'POST'); } catch (error) { toast(error.message); } };
$('menu').onclick = () => $('sidebar').classList.toggle('open');
document.querySelectorAll('[data-view]').forEach(button => {
  button.onclick = () => { view = button.dataset.view; $('search').value = ''; render(); $('sidebar').classList.remove('open'); };
});
$('search').oninput = render; $('sort').onchange = render;
$('add').onclick = () => edit(undefined, view === 'authenticator'); $('empty-add').onclick = $('add').onclick;
$('close-dialog').onclick = () => $('entry-dialog').close();
$('entry-dialog').addEventListener('close', () => { $('entry-form').reset(); $('entry-error').textContent = ''; });
$('entry-generate').onclick = () => { $('password').value = generatePassword(); };
$('entry-form').onsubmit = async event => {
  event.preventDefault(); const data = {};
  for (const key of ['name', 'username', 'password', 'url', 'notes', 'category']) data[key] = $(key).value;
  const secret = $('totp-secret').value.trim();
  data.totp = !secret ? null : secret.toLowerCase().startsWith('otpauth:') ? secret : {
    secret, algorithm: $('totp-algorithm').value, digits: Number($('totp-digits').value), period: Number($('totp-period').value)
  };
  if (!data.password && !data.totp) { $('entry-error').textContent = 'Add a password, an authenticator key, or both.'; return; }
  data.favorite = $('favorite').checked; $('save-entry').disabled = true;
  try {
    const id = $('entry-id').value;
    const saved = await api(id ? `entries/${id}` : 'entries', id ? 'PUT' : 'POST', data);
    entries = id ? entries.map(entry => entry.id === id ? saved : entry) : [...entries, saved];
    selectedId = saved.id; codeCache.delete(saved.id);
    $('entry-dialog').close(); render(); toast('Account saved.');
  } catch (error) { $('entry-error').textContent = error.message; }
  finally { $('save-entry').disabled = false; }
};
$('delete').onclick = () => $('delete-dialog').showModal();
$('cancel-delete').onclick = () => $('delete-dialog').close();
$('confirm-delete').onclick = async () => {
  const id = $('entry-id').value; $('confirm-delete').disabled = true;
  try {
    await api(`entries/${id}`, 'DELETE'); entries = entries.filter(entry => entry.id !== id); codeCache.delete(id);
    $('delete-dialog').close(); $('entry-dialog').close(); render(); toast('Account deleted.');
  } catch (error) { $('delete-dialog').close(); $('entry-error').textContent = error.message; }
  finally { $('confirm-delete').disabled = false; }
};
for (const id of ['length', 'lowercase', 'uppercase', 'numbers', 'symbols', 'exclude-ambiguous']) $(id).oninput = generate;
$('regenerate').onclick = generate; $('copy-generated').onclick = () => copyText($('generated').textContent);
$('use-generated').onclick = () => { const password = $('generated').textContent; if (password) { edit(); $('password').value = password; } };
document.addEventListener('keydown', event => {
  if (event.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName) && !$('vault').hidden && view !== 'generator' && !$('entry-dialog').open) { event.preventDefault(); $('search').focus(); }
});
for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, () => { lastActivity = Date.now(); }, { passive: true });
function checkIdle() {
  if (!$('vault').hidden && Date.now() - lastActivity >= 15 * 60 * 1000) { showAuth(); api('lock', 'POST').catch(() => {}); }
}
setInterval(() => { checkIdle(); tickCodes(); }, 1000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) { checkIdle(); tickCodes(); } });
(async () => {
  try { const status = await api('status'); initialized = status.initialized; if (status.unlocked) await loadVault(); else showAuth(); }
  catch (error) { showAuth(); $('auth-error').textContent = error.message; }
})();
