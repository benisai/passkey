'use strict';
const $ = (id) => document.getElementById(id);
let entries = [], view = 'all', initialized = false, lastActivity = Date.now(), toastTimer;
async function api(path, method = 'GET', data) {
  const response = await fetch(`/api/${path}`, {method, headers: {'Content-Type': 'application/json', 'X-Vault-Request': '1'}, ...(data === undefined ? {} : {body: JSON.stringify(data)})});
  const result = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== 'unlock') showAuth();
    throw new Error(result.error || 'Something went wrong. Please try again.');
  }
  return result;
}
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3000); }
function showAuth() {
  entries = []; $('entries').replaceChildren(); $('entry-form').reset(); $('generated').textContent = ''; $('search').value = '';
  document.querySelectorAll('dialog[open]').forEach(d => d.close()); $('vault').hidden = true; $('auth').hidden = false;
  $('master').value = ''; $('confirm-master').value = ''; $('master').type = 'password'; $('toggle-master').textContent = 'Show';
  $('auth-title').textContent = initialized ? 'Welcome home.' : 'A safer place to start.';
  $('auth-description').textContent = initialized ? 'Unlock your vault to pick up where you left off.' : 'Create a master password to make this vault yours.';
  $('auth-submit').textContent = initialized ? 'Unlock vault ↗' : 'Create your vault ↗';
  $('confirm-wrap').hidden = initialized; $('confirm-master').required = !initialized;
  $('master').minLength = initialized ? 1 : 12; $('master').autocomplete = initialized ? 'current-password' : 'new-password';
  $('auth-note').textContent = initialized ? 'Your vault locks automatically after 15 minutes of inactivity.' : 'Use at least 12 characters. Keep it safe: your master password cannot be recovered.';
  $('master').focus();
}
async function loadVault() {
  entries = await api('entries'); initialized = true; lastActivity = Date.now();
  $('auth').hidden = true; $('vault').hidden = false; $('auth-error').textContent = ''; $('master').value = ''; $('confirm-master').value = '';
  render();
}
function element(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; }
function render() {
  const favorites = entries.filter(e => e.favorite).length;
  $('total-stat').textContent = $('all-count').textContent = entries.length;
  $('favorite-stat').textContent = $('fav-count').textContent = favorites;
  document.querySelectorAll('[data-view]').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  const title = view === 'all' ? 'All passwords' : view === 'favorites' ? 'Favorites' : view === 'generator' ? 'Password generator' : view;
  $('page-title').replaceChildren(document.createTextNode(title), element('span', '', '.'));
  $('breadcrumb').textContent = title;
  $('page-description').textContent = view === 'generator' ? 'Strong passwords, without the guesswork.' : view === 'favorites' ? 'Your everyday essentials, a little closer.' : 'Everything you need, safely in one place.';
  $('vault-content').hidden = view === 'generator'; $('generator').hidden = view !== 'generator';
  if (view === 'generator') { if (!$('generated').textContent) generate(); return; }
  const query = $('search').value.toLowerCase();
  const filtered = entries.filter(e => (view === 'all' || (view === 'favorites' ? e.favorite : e.category === view)) && [e.name,e.username,e.url,e.category].some(v => v.toLowerCase().includes(query)));
  filtered.sort($('sort').value === 'updated' ? (a,b) => b.updated-a.updated : (a,b) => a.name.localeCompare(b.name));
  $('entries').replaceChildren();
  filtered.forEach(entry => {
    const row = element('div', 'entry-row');
    const name = element('button','entry-name'); name.type = 'button'; name.title = `Edit ${entry.name}`;
    name.append(element('span','entry-avatar',entry.name.charAt(0).toUpperCase()));
    let hostname = 'Password';
    try { if (entry.url) hostname = new URL(entry.url).hostname; } catch { hostname = entry.url; }
    const info = element('div'); info.append(element('strong','',entry.name),element('small','',hostname)); name.append(info); name.onclick = () => edit(entry);
    const actions = element('div','row-actions');
    const star = element('button', `icon-button${entry.favorite ? ' is-favorite' : ''}`, entry.favorite ? '★' : '☆'); star.type='button'; star.setAttribute('aria-label',`${entry.favorite ? 'Unfavorite' : 'Favorite'} ${entry.name}`); star.setAttribute('aria-pressed', String(entry.favorite));
    star.onclick = async () => { try { const updated = await api(`entries/${entry.id}`, 'PUT', {...entry, favorite: !entry.favorite}); entries = entries.map(e => e.id === entry.id ? updated : e); render(); } catch(e) { toast(e.message); } };
    const copy = element('button','icon-button','⧉'); copy.type='button'; copy.setAttribute('aria-label',`Copy password for ${entry.name}`); copy.onclick=()=>copyText(entry.password);
    actions.append(star,copy); row.append(name,element('span','entry-username',entry.username || '—'),element('span','category-pill',entry.category),actions); $('entries').append(row);
  });
  $('empty').hidden = filtered.length > 0;
  $('empty').querySelector('h2').textContent = entries.length ? 'Nothing here just yet.' : 'A fresh start for your passwords.';
  $('empty').querySelector('p').textContent = entries.length ? 'Try another search, or add a password to this collection.' : 'Add your first login. We’ll keep it safe and easy to find.';
  $('results').textContent = `${filtered.length} password${filtered.length === 1 ? '' : 's'}`;
}
function edit(entry) {
  $('entry-form').reset(); $('entry-error').textContent = ''; $('entry-id').value = entry?.id || ''; $('dialog-title').textContent = entry ? 'Edit password' : 'Add a password';
  for (const key of ['name','username','password','url','notes','category']) $(key).value = entry?.[key] || (key === 'category' ? (['Personal','Work','Finance','Social','Other'].includes(view) ? view : 'Personal') : '');
  $('favorite').checked = entry?.favorite || false; $('password').type='password'; $('toggle-password').textContent='Show'; $('delete').hidden = !entry; $('entry-dialog').showModal();
}
function randomIndex(limit) { const array = new Uint32Array(1); const ceiling = Math.floor(2**32 / limit) * limit; do { crypto.getRandomValues(array); } while(array[0] >= ceiling); return array[0] % limit; }
function makePassword(length = Number($('length').value), symbols = $('symbols').checked) {
  const groups = ['abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ','0123456789']; if(symbols) groups.push('!@#$%^&*()-_=+[]{}?');
  const alphabet = groups.join(''); const chars = groups.map(g => g[randomIndex(g.length)]);
  while(chars.length < length) chars.push(alphabet[randomIndex(alphabet.length)]);
  for(let i=chars.length-1;i>0;i--) { const j=randomIndex(i+1); [chars[i],chars[j]]=[chars[j],chars[i]]; }
  return chars.join('');
}
function generate() { $('generated').textContent=makePassword(); $('length-value').textContent=$('length').value; }
async function copyText(value) { try { await navigator.clipboard.writeText(value); toast('Password copied to clipboard.'); } catch { toast('Clipboard unavailable. Open the entry and use Show to copy manually.'); } }
$('auth-form').onsubmit=async event=>{event.preventDefault(); $('auth-error').textContent=''; if(!initialized && $('master').value!==$('confirm-master').value){$('auth-error').textContent='Your passwords do not match.';return;} $('auth-submit').disabled=true; try {await api(initialized?'unlock':'setup','POST',{password:$('master').value}); await loadVault();} catch(e){$('auth-error').textContent=e.message;} finally{$('auth-submit').disabled=false;}};
$('toggle-master').onclick=()=>toggle('master','toggle-master');
function toggle(input,button) { const hidden=$(input).type==='password'; $(input).type=hidden?'text':'password'; $(button).textContent=hidden?'Hide':'Show'; }
$('toggle-password').onclick=()=>toggle('password','toggle-password');
$('lock').onclick=async()=>{try {await api('lock','POST');showAuth();}catch(e){showAuth();toast(e.message);}};
$('menu').onclick=()=>$('sidebar').classList.toggle('open');
document.querySelectorAll('[data-view]').forEach(button=>button.onclick=()=>{view=button.dataset.view;$('search').value='';render();$('sidebar').classList.remove('open');});
$('search').oninput=render; $('sort').onchange=render; $('add').onclick=()=>edit();$('empty-add').onclick=()=>edit();
$('close-dialog').onclick=()=>$('entry-dialog').close();
$('entry-dialog').addEventListener('close',()=>{$('entry-form').reset();$('entry-error').textContent='';});
$('entry-generate').onclick=()=>{$('password').value=makePassword(20,true);};
$('entry-form').onsubmit=async event=>{event.preventDefault();const data={};for(const key of ['name','username','password','url','notes','category'])data[key]=$(key).value; data.favorite=$('favorite').checked; $('save-entry').disabled=true;try{const id=$('entry-id').value;const saved=await api(id?`entries/${id}`:'entries',id?'PUT':'POST',data);entries=id?entries.map(e=>e.id===id?saved:e):[...entries,saved];$('entry-dialog').close();render();toast('Password saved.');}catch(e){$('entry-error').textContent=e.message;}finally{$('save-entry').disabled=false;}};
$('delete').onclick=()=>$('delete-dialog').showModal(); $('cancel-delete').onclick=()=>$('delete-dialog').close();
$('confirm-delete').onclick=async()=>{const id=$('entry-id').value;try{await api(`entries/${id}`,'DELETE');entries=entries.filter(e=>e.id!==id);$('delete-dialog').close();$('entry-dialog').close();render();toast('Password deleted.');}catch(e){$('delete-dialog').close();$('entry-error').textContent=e.message;}};
$('length').oninput=generate;$('symbols').onchange=generate;$('regenerate').onclick=generate;$('copy-generated').onclick=()=>copyText($('generated').textContent);
document.addEventListener('keydown',e=>{if(e.key==='/' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName) && !$('vault').hidden && view!=='generator' && !$('entry-dialog').open){e.preventDefault();$('search').focus();}});
for(const event of ['pointerdown','keydown','input'])document.addEventListener(event,()=>{lastActivity=Date.now();},{passive:true});
setInterval(async()=>{if(!$('vault').hidden && Date.now()-lastActivity>=15*60*1000){showAuth();try{await api('lock','POST');}catch{}}},1000);
// Clear plaintext from the DOM when returning after the idle timeout.
document.addEventListener('visibilitychange',()=>{if(!document.hidden && !$('vault').hidden && Date.now()-lastActivity>=15*60*1000){showAuth();api('lock','POST').catch(()=>{});}});
(async()=>{try{const status=await api('status');initialized=status.initialized;if(status.unlocked)await loadVault();else showAuth();}catch(e){showAuth();$('auth-error').textContent=e.message;}})();
