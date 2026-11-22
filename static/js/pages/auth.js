/* VAULT - pages/auth.js
   Sign-in and first-run setup page (templates/accounts/auth.html):
   show / hide password, Caps Lock hint, required-field check, and a busy "Signing in..." button.
   The form itself is a normal POST to the server (no JavaScript needed to sign in). */

const form = document.getElementById('loginForm');
const user = document.getElementById('username');
const pwd = document.getElementById('password');
const statusEl = document.getElementById('status');
const btn = document.getElementById('submitBtn');
const btnLabel = btn.querySelector('.label');

/* show / hide password */
document.getElementById('togglePassword').addEventListener('click', e => {
  const show = pwd.type === 'password';
  pwd.type = show ? 'text' : 'password';
  e.currentTarget.setAttribute('aria-pressed', show);
  e.currentTarget.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  pwd.focus();
});

/* caps lock warning */
const caps = document.getElementById('caps');
['keyup','keydown'].forEach(t => pwd.addEventListener(t, e => {
  if (e.getModifierState) caps.classList.toggle('on', e.getModifierState('CapsLock'));
}));
pwd.addEventListener('blur', () => caps.classList.remove('on'));

/* clear the invalid state while typing */
[user, pwd].forEach(i => i.addEventListener('input', () => i.parentElement.classList.remove('invalid')));

function setStatus(msg, cls){ statusEl.textContent = msg; statusEl.className = 'status ' + (cls || ''); }
function shake(){ form.classList.remove('shake'); void form.offsetWidth; form.classList.add('shake'); }

/* the server answered with an error (wrong password, lockout): the card shakes once on load */
form.addEventListener('animationend', e => { if (e.animationName === 'shake') form.classList.remove('shake'); });

form.addEventListener('submit', e => {
  const u = user.value.trim(), p = pwd.value, confirm = form.elements.confirm;
  user.parentElement.classList.toggle('invalid', !u);
  pwd.parentElement.classList.toggle('invalid', !p);
  if (!u || !p){ e.preventDefault(); setStatus('Username and password are required.', 'err'); shake(); (u ? pwd : user).focus(); return; }
  if (confirm && confirm.value !== p){
    e.preventDefault(); confirm.parentElement.classList.add('invalid');
    setStatus('The two passwords are different. Type the same password in both fields.', 'err'); shake(); confirm.focus(); return;
  }
  if (btn.disabled){ e.preventDefault(); return; }
  btn.disabled = true; btn.classList.add('loading');
  btnLabel.textContent = confirm ? 'Please wait…' : 'Signing in…';
  setStatus('', '');
});
