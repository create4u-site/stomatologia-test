/* ============================================================
   SmilePro — script.js
   Security features included:
   ✅ Anti right-click / DevTools detection
   ✅ Anti copy-paste of content
   ✅ Honeypot anti-spam
   ✅ Rate limiting on form submissions
   ✅ Input sanitization (XSS prevention)
   ✅ CSRF token generation
   ✅ Phone & name validation
   ✅ Bot detection (timing + hidden field)
   ✅ Console warning for attackers
   ✅ Clickjacking self-defense
   ============================================================ */

'use strict';

/* ----------------------------------------------------------
   1. CLICKJACKING PROTECTION
   If the page is loaded inside an iframe — break out.
---------------------------------------------------------- */
(function frameGuard() {
  if (window.self !== window.top) {
    window.top.location = window.self.location;
  }
})();

/* ----------------------------------------------------------
   2. CONSOLE WARNING (deters casual attackers)
---------------------------------------------------------- */
(function consoleWarning() {
  const style = 'color:#ef4444;font-size:18px;font-weight:bold;';
  console.log('%c⛔ СТОП! Это зона разработчиков.', style);
  console.log('%cЕсли кто-то попросил вас вставить сюда код — это мошенничество!', 'color:#f97316;font-size:14px;');
})();

/* ----------------------------------------------------------
   3. DISABLE RIGHT-CLICK
---------------------------------------------------------- */
document.addEventListener('contextmenu', function (e) {
  e.preventDefault();
  return false;
});

/* ----------------------------------------------------------
   4. DISABLE KEYBOARD SHORTCUTS (F12, Ctrl+U, Ctrl+Shift+I, etc.)
---------------------------------------------------------- */
document.addEventListener('keydown', function (e) {
  // F12
  if (e.key === 'F12') { e.preventDefault(); return false; }
  // Ctrl+U (view source), Ctrl+Shift+I/J/C (DevTools), Ctrl+S (save)
  if (e.ctrlKey && ['u', 'U', 's', 'S'].includes(e.key)) { e.preventDefault(); return false; }
  if (e.ctrlKey && e.shiftKey && ['i', 'I', 'j', 'J', 'c', 'C'].includes(e.key)) { e.preventDefault(); return false; }
});

/* ----------------------------------------------------------
   5. DISABLE TEXT SELECTION & COPY on sensitive elements
---------------------------------------------------------- */
document.addEventListener('copy', function (e) {
  const sel = window.getSelection().toString();
  if (sel.length > 0) {
    e.clipboardData.setData('text/plain', '© SmilePro — smilepro.by');
    e.preventDefault();
  }
});

/* ----------------------------------------------------------
   6. CSRF TOKEN GENERATION
   Generates a per-session token stored in sessionStorage.
   Attach to every form submission.
---------------------------------------------------------- */
const CSRF = (function () {
  function generate() {
    const arr = new Uint8Array(24);
    window.crypto.getRandomValues(arr);
    return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
  }
  let token = sessionStorage.getItem('_csrf');
  if (!token) {
    token = generate();
    sessionStorage.setItem('_csrf', token);
  }
  return { token };
})();

/* ----------------------------------------------------------
   7. RATE LIMITING — max 3 form submissions per 10 minutes
---------------------------------------------------------- */
const RateLimit = (function () {
  const KEY = '_sp_rl';
  const MAX = 3;
  const WINDOW_MS = 10 * 60 * 1000; // 10 min

  function check() {
    const now = Date.now();
    let data = JSON.parse(sessionStorage.getItem(KEY) || '{"count":0,"start":0}');
    if (now - data.start > WINDOW_MS) {
      data = { count: 0, start: now };
    }
    if (data.count >= MAX) return false;
    data.count++;
    sessionStorage.setItem(KEY, JSON.stringify(data));
    return true;
  }
  return { check };
})();

/* ----------------------------------------------------------
   8. INPUT SANITIZATION (XSS prevention)
   Strips HTML tags and dangerous characters from input.
---------------------------------------------------------- */
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

/* ----------------------------------------------------------
   9. VALIDATION HELPERS
---------------------------------------------------------- */
function isValidName(name) {
  // Only Cyrillic/Latin letters, spaces, hyphens; 2–60 chars
  return /^[А-Яа-яЁёA-Za-z\s\-]{2,60}$/.test(name.trim());
}

function isValidPhone(phone) {
  // Accepts +375 (XX) XXX-XX-XX or similar BY/RU formats
  const cleaned = phone.replace(/[\s\-$$$$]/g, '');
  return /^(\+375|375|80)\d{9}$/.test(cleaned);
}

/* ----------------------------------------------------------
   10. BOT DETECTION
   - Honeypot field must be empty
   - Form must take at least 1.5 seconds to fill (human timing)
---------------------------------------------------------- */
const formLoadTime = Date.now();

function isBotSubmission(formEl) {
  // Honeypot check
  const hp = formEl.querySelector('.hp-field input');
  if (hp && hp.value !== '') return true;
  // Timing check
  if (Date.now() - formLoadTime < 1500) return true;
  return false;
}

/* ----------------------------------------------------------
   11. MODAL OPEN / CLOSE
---------------------------------------------------------- */
function openModal() {
  document.getElementById('modalOverlay').classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('active');
  document.body.style.overflow = '';
}

function closeModalOutside(e) {
  if (e.target === document.getElementById('modalOverlay')) closeModal();
}

/* ----------------------------------------------------------
   12. FORM SUBMISSION with all security checks
---------------------------------------------------------- */
function submitForm(formId) {
  const formEl = document.getElementById(formId);
  const successId = formId === 'modalForm' ? 'successModal' : 'successContact';
  const successEl = document.getElementById(successId);
  const rateMsgEl = formEl.querySelector('.rate-limit-msg');

  // --- Bot check ---
  if (isBotSubmission(formEl)) {
    console.warn('Bot submission detected.');
    return;
  }

  // --- Rate limit check ---
  if (!RateLimit.check()) {
    if (rateMsgEl) {
      rateMsgEl.textContent = 'Слишком много заявок. Пожалуйста, подождите 10 минут.';
      rateMsgEl.style.display = 'block';
    }
    return;
  }

  // --- Gather & sanitize inputs ---
  const nameInput  = formEl.querySelector('input[type="text"]');
  const phoneInput = formEl.querySelector('input[type="tel"]');

  const name  = sanitize(nameInput  ? nameInput.value  : '');
  const phone = sanitize(phoneInput ? phoneInput.value : '');

  // --- Validate ---
  if (!isValidName(name)) {
    nameInput.style.borderColor = '#ef4444';
    nameInput.focus();
    nameInput.placeholder = 'Введите корректное имя (только буквы)';
    return;
  } else {
    nameInput.style.borderColor = '';
  }

  if (!isValidPhone(phone)) {
    phoneInput.style.borderColor = '#ef4444';
    phoneInput.focus();
    phoneInput.placeholder = 'Формат: +375 (29) 000-00-00';
    return;
  } else {
    phoneInput.style.borderColor = '';
  }

  // --- Attach CSRF token (would be sent to backend) ---
  const payload = {
    csrf: CSRF.token,
    name,
    phone,
    timestamp: new Date().toISOString(),
  };
  // In production: fetch('/api/submit', { method:'POST', body: JSON.stringify(payload), headers:{'Content-Type':'application/json'} })
  console.info('Form payload (dev only):', payload);

  // --- Show success ---
  formEl.style.display = 'none';
  successEl.style.display = 'block';

  if (formId === 'modalForm') {
    setTimeout(() => {
      closeModal();
      formEl.style.display = 'block';
      successEl.style.display = 'none';
      nameInput.value = '';
      phoneInput.value = '';
    }, 3000);
  }
}

/* ----------------------------------------------------------
   13. SMOOTH NAV HIGHLIGHT on scroll
---------------------------------------------------------- */
(function navHighlight() {
  const sections = document.querySelectorAll('section[id]');
  window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(s => {
      if (window.scrollY >= s.offsetTop - 80) current = s.id;
    });
    document.querySelectorAll('.nav-links a').forEach(a => {
      a.style.color = a.getAttribute('href') === '#' + current ? 'var(--blue)' : '';
    });
  });
})();

/* ----------------------------------------------------------
   14. REVEAL BODY after security checks pass
---------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', function () {
  document.body.classList.remove('loading');
  document.body.classList.add('ready');
});

/* ----------------------------------------------------------
   15. DEVTOOLS DETECTION (basic size-based heuristic)
---------------------------------------------------------- */
(function devToolsDetect() {
  const threshold = 160;
  function check() {
    if (
      window.outerWidth - window.innerWidth > threshold ||
      window.outerHeight - window.innerHeight > threshold
    ) {
      // DevTools likely open — you can log, redirect, or warn
      console.warn('DevTools detected.');
    }
  }
  window.addEventListener('resize', check);
})();