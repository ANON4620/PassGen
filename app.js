/**
 * PassGen — Secure Password Generator
 * app.js — All logic runs client-side, nothing is sent to any server.
 */

'use strict';

/* ======================================================
   Character Sets
   ====================================================== */
const CHARS = {
  uppercase:  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase:  'abcdefghijklmnopqrstuvwxyz',
  numbers:    '0123456789',
  symbols:    '!@#$%^&*()-_=+[]{}|;:,.<>?/',
};

const AMBIGUOUS = /[O0lI1|]/g;

/* ======================================================
   State
   ====================================================== */
let currentPassword = '';
let passwordHistory  = [];  // max 10 entries

/* ======================================================
   DOM References
   ====================================================== */
const passwordText     = document.getElementById('password-text');
const copyBtn          = document.getElementById('copy-btn');
const generateBtn      = document.getElementById('generate-btn');
const copyIcon         = copyBtn.querySelector('.copy-icon');
const checkIcon        = copyBtn.querySelector('.check-icon');
const lengthSlider     = document.getElementById('length-slider');
const lengthNumber     = document.getElementById('length-number');
const sliderFill       = document.getElementById('slider-fill');

const optUppercase     = document.getElementById('opt-uppercase');
const optLowercase     = document.getElementById('opt-lowercase');
const optNumbers       = document.getElementById('opt-numbers');
const optSymbols       = document.getElementById('opt-symbols');
const optExcludeAmbi   = document.getElementById('opt-exclude-ambiguous');

const statEntropy      = document.getElementById('stat-entropy');
const statCharset      = document.getElementById('stat-charset');
const statCrack        = document.getElementById('stat-crack');

const strengthBars     = [
  document.getElementById('bar-1'),
  document.getElementById('bar-2'),
  document.getElementById('bar-3'),
  document.getElementById('bar-4'),
];
const strengthLabel    = document.getElementById('strength-label');

const historyList      = document.getElementById('history-list');
const historyEmpty     = document.getElementById('history-empty');
const clearHistoryBtn  = document.getElementById('clear-history-btn');
const exportHistoryBtn = document.getElementById('export-history-btn');
const themeToggleBtn   = document.getElementById('theme-toggle');

const toast            = document.getElementById('toast');

/* ======================================================
   Theme Management
   ====================================================== */

const THEME_KEY = 'passgen-theme';

/**
 * Applies a theme ('dark' | 'light') to the document and saves it.
 */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem(THEME_KEY, theme);
}

/**
 * Reads saved theme from localStorage (defaults to 'dark').
 */
function loadTheme() {
  return localStorage.getItem(THEME_KEY) || 'dark';
}

/**
 * Toggles between light and dark.
 */
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

/* ======================================================
   Password Generation
   ====================================================== */

/**
 * Builds the full character pool based on settings.
 * Guarantees at least one character from each enabled set.
 */
function buildCharPool() {
  const opts = getOptions();
  if (!opts.uppercase && !opts.lowercase && !opts.numbers && !opts.symbols) {
    // Fallback — show error
    return null;
  }

  let pool = '';
  if (opts.uppercase) pool += CHARS.uppercase;
  if (opts.lowercase) pool += CHARS.lowercase;
  if (opts.numbers)   pool += CHARS.numbers;
  if (opts.symbols)   pool += CHARS.symbols;

  if (opts.excludeAmbiguous) {
    pool = pool.replace(AMBIGUOUS, '');
  }

  return pool;
}

/**
 * Returns current option settings.
 */
function getOptions() {
  return {
    length:          parseInt(lengthSlider.value, 10),
    uppercase:       optUppercase.checked,
    lowercase:       optLowercase.checked,
    numbers:         optNumbers.checked,
    symbols:         optSymbols.checked,
    excludeAmbiguous: optExcludeAmbi.checked,
  };
}

/**
 * Cryptographically secure random integer in [0, max).
 */
function secureRandInt(max) {
  const arr = new Uint32Array(1);
  let result;
  // Rejection sampling to avoid modulo bias
  const limit = Math.floor(0xFFFFFFFF / max) * max;
  do {
    crypto.getRandomValues(arr);
  } while (arr[0] >= limit);
  return arr[0] % max;
}

/**
 * Generates a random password and guarantees at least
 * one character from each enabled set.
 */
function generatePassword() {
  const opts = getOptions();
  const pool = buildCharPool();

  if (!pool) {
    showToast('⚠️ Enable at least one character type!', 'warning');
    return;
  }

  const len = opts.length;
  const guaranteed = [];

  // Build guaranteed characters
  if (opts.uppercase) {
    let upper = CHARS.uppercase;
    if (opts.excludeAmbiguous) upper = upper.replace(AMBIGUOUS, '');
    if (upper.length > 0) guaranteed.push(upper[secureRandInt(upper.length)]);
  }
  if (opts.lowercase) {
    let lower = CHARS.lowercase;
    if (opts.excludeAmbiguous) lower = lower.replace(AMBIGUOUS, '');
    if (lower.length > 0) guaranteed.push(lower[secureRandInt(lower.length)]);
  }
  if (opts.numbers) {
    let nums = CHARS.numbers;
    if (opts.excludeAmbiguous) nums = nums.replace(AMBIGUOUS, '');
    if (nums.length > 0) guaranteed.push(nums[secureRandInt(nums.length)]);
  }
  if (opts.symbols) {
    guaranteed.push(CHARS.symbols[secureRandInt(CHARS.symbols.length)]);
  }

  // Fill remaining length with random pool chars
  const remaining = len - guaranteed.length;
  const rand = [];
  for (let i = 0; i < remaining; i++) {
    rand.push(pool[secureRandInt(pool.length)]);
  }

  // Shuffle guaranteed + random together (Fisher-Yates via crypto)
  const combined = [...guaranteed, ...rand];
  for (let i = combined.length - 1; i > 0; i--) {
    const j = secureRandInt(i + 1);
    [combined[i], combined[j]] = [combined[j], combined[i]];
  }

  return combined.join('');
}

/* ======================================================
   Strength Calculation
   ====================================================== */

/**
 * Calculates password entropy in bits.
 * entropy = log2(poolSize ^ length) = length * log2(poolSize)
 */
function calcEntropy(password, poolSize) {
  if (!password || poolSize === 0) return 0;
  return Math.round(password.length * Math.log2(poolSize));
}

/**
 * Maps entropy to a strength level 1–4.
 */
function entropyToLevel(entropy) {
  if (entropy < 40)  return 1; // Weak
  if (entropy < 60)  return 2; // Fair
  if (entropy < 90)  return 3; // Good
  return 4;                    // Strong
}

const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
const STRENGTH_CLASSES = ['', 'level-1', 'level-2', 'level-3', 'level-4'];

function updateStrength(password) {
  const pool = buildCharPool();
  if (!pool || !password) {
    strengthBars.forEach(b => {
      b.className = 'strength-bar';
    });
    strengthLabel.textContent = '—';
    strengthLabel.className   = 'strength-label';
    statEntropy.textContent   = '—';
    statCharset.textContent   = '—';
    statCrack.textContent     = '—';
    return;
  }

  const poolSize = pool.length;
  const entropy  = calcEntropy(password, poolSize);
  const level    = entropyToLevel(entropy);

  // Update bars
  strengthBars.forEach((bar, idx) => {
    bar.className = 'strength-bar' + (idx < level ? ` active-${level}` : '');
  });

  // Update label
  strengthLabel.textContent = STRENGTH_LABELS[level];
  strengthLabel.className   = `strength-label ${STRENGTH_CLASSES[level]}`;

  // Update stats
  statEntropy.textContent = entropy.toString();
  statCharset.textContent = poolSize.toString();
  statCrack.textContent   = estimateCrackTime(entropy);
}

/**
 * Very rough estimation of time to crack via brute force at 10 billion guesses/sec.
 */
function estimateCrackTime(entropy) {
  if (entropy === 0) return '—';
  // 10^10 guesses/sec (a modern GPU cluster)
  const guessesPerSec = 1e10;
  // avg time = (2^entropy / 2) / guessesPerSec
  const seconds = Math.pow(2, entropy) / 2 / guessesPerSec;

  if (seconds < 1)         return '< 1s';
  if (seconds < 60)        return `${Math.round(seconds)}s`;
  if (seconds < 3600)      return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400)     return `${Math.round(seconds / 3600)}h`;
  if (seconds < 31536000)  return `${Math.round(seconds / 86400)}d`;

  const years = seconds / 31536000;
  if (years < 1e3)  return `${Math.round(years)}y`;
  if (years < 1e6)  return `${(years / 1e3).toFixed(0)}ky`;
  if (years < 1e9)  return `${(years / 1e6).toFixed(0)}My`;
  if (years < 1e12) return `${(years / 1e9).toFixed(0)}Gy`;
  return '∞';
}

/* ======================================================
   UI Updates
   ====================================================== */

function updateSliderFill() {
  const slider = lengthSlider;
  const min    = parseFloat(slider.min);
  const max    = parseFloat(slider.max);
  const val    = parseFloat(slider.value);
  const pct    = ((val - min) / (max - min)) * 100;
  slider.style.background = `linear-gradient(to right, #7c3aed ${pct}%, rgba(255,255,255,0.08) ${pct}%)`;
}

function setLength(val) {
  const n = Math.min(Math.max(parseInt(val, 10) || 16, 4), 128);
  lengthSlider.value = n;
  lengthNumber.value = n;
  updateSliderFill();
}

/* ======================================================
   Clipboard
   ====================================================== */

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity  = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  }
}

let copyResetTimer;

async function handleCopy(password) {
  const ok = await copyToClipboard(password);
  if (ok) {
    copyIcon.classList.add('hidden');
    checkIcon.classList.remove('hidden');
    copyBtn.classList.add('copied');
    showToast('✅ Password copied to clipboard!');
    clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => {
      copyIcon.classList.remove('hidden');
      checkIcon.classList.add('hidden');
      copyBtn.classList.remove('copied');
    }, 2000);
  } else {
    showToast('⚠️ Failed to copy. Please copy manually.');
  }
}

/* ======================================================
   Toast
   ====================================================== */

let toastTimer;
function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
  }, 2500);
}

/* ======================================================
   Password History
   ====================================================== */

function strengthLevel(password) {
  const pool = buildCharPool();
  if (!pool || !password) return 0;
  return entropyToLevel(calcEntropy(password, pool.length));
}

function addToHistory(password) {
  const level = strengthLevel(password);
  passwordHistory.unshift({ password, level });
  if (passwordHistory.length > 10) passwordHistory.pop();
  renderHistory();
}

function renderHistory() {
  // Remove all dynamic history items (not the empty state)
  const items = historyList.querySelectorAll('.history-item');
  items.forEach(el => el.remove());

  if (passwordHistory.length === 0) {
    historyEmpty.style.display = 'flex';
    return;
  }

  historyEmpty.style.display = 'none';

  const badgeClass  = ['', 'badge-weak', 'badge-fair', 'badge-good', 'badge-strong'];
  const badgeLabel  = ['', 'Weak', 'Fair', 'Good', 'Strong'];

  passwordHistory.forEach(({ password, level }, idx) => {
    const item = document.createElement('div');
    item.className = 'history-item';
    item.setAttribute('role', 'listitem');

    const truncated = password.length > 40 ? password.slice(0, 40) + '…' : password;

    item.innerHTML = `
      <span class="history-pw" title="${escapeHtml(password)}">${escapeHtml(truncated)}</span>
      <div class="history-meta">
        <span class="history-badge ${badgeClass[level]}">${badgeLabel[level]}</span>
        <button class="history-copy-btn" aria-label="Copy password ${idx + 1}" title="Copy password">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </button>
      </div>
    `;

    // Copy button in history
    item.querySelector('.history-copy-btn').addEventListener('click', async (e) => {
      e.stopPropagation();
      const ok = await copyToClipboard(password);
      if (ok) showToast('✅ Copied from history!');
    });

    historyList.appendChild(item);
  });
}

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ======================================================
   Main Generate Flow
   ====================================================== */

function generate() {
  // Animate button
  generateBtn.classList.add('spinning');
  setTimeout(() => generateBtn.classList.remove('spinning'), 600);

  const pw = generatePassword();
  if (!pw) return;

  currentPassword = pw;

  // Update display
  passwordText.textContent = pw;
  passwordText.classList.remove('placeholder');

  // Enable copy
  copyBtn.disabled = false;

  // Reset copy state
  copyIcon.classList.remove('hidden');
  checkIcon.classList.add('hidden');
  copyBtn.classList.remove('copied');

  // Strength
  updateStrength(pw);

  // History
  addToHistory(pw);
}

/* ======================================================
   Event Listeners
   ====================================================== */

// Generate on button click
generateBtn.addEventListener('click', generate);

// Copy main password
copyBtn.addEventListener('click', () => {
  if (currentPassword) handleCopy(currentPassword);
});

// Keyboard shortcut: Ctrl/Cmd + G to generate, Ctrl/Cmd + C to copy
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'g') {
    e.preventDefault();
    generate();
  }
});

// Slider — update length display only
lengthSlider.addEventListener('input', () => {
  setLength(lengthSlider.value);
});

// Number input — update length display only
lengthNumber.addEventListener('change', () => {
  setLength(lengthNumber.value);
});

lengthNumber.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    setLength(lengthNumber.value);
  }
});

// Character option toggles — no auto-regenerate

// Clear history
clearHistoryBtn.addEventListener('click', () => {
  passwordHistory = [];
  renderHistory();
  showToast('🗑️ History cleared');
});

// Export history
exportHistoryBtn.addEventListener('click', exportHistory);

// Theme toggle
themeToggleBtn.addEventListener('click', toggleTheme);

/* ======================================================
   Export History
   ====================================================== */

/**
 * Exports the current password history as a plain-text .txt file.
 */
function exportHistory() {
  if (passwordHistory.length === 0) {
    showToast('⚠️ No passwords in history to export!');
    return;
  }

  const STRENGTH_LABELS = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  const now = new Date();
  const dateStr = now.toLocaleString();

  const lines = [
    '╔══════════════════════════════════════════════╗',
    '║        PassGen — Password History Export      ║',
    '╚══════════════════════════════════════════════╝',
    `Exported on: ${dateStr}`,
    `Total passwords: ${passwordHistory.length}`,
    '──────────────────────────────────────────────',
    '',
    ...passwordHistory.map(({ password, level }, i) =>
      `${String(i + 1).padStart(2, '0')}. [${STRENGTH_LABELS[level]}] ${password}`
    ),
    '',
    '──────────────────────────────────────────────',
    'Generated by PassGen — https://passgen.vercel.app',
    'Passwords are created using the Web Crypto API.',
    'Keep this file secure and delete when no longer needed.',
  ];

  const content  = lines.join('\n');
  const blob     = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url      = URL.createObjectURL(blob);
  const a        = document.createElement('a');
  a.href         = url;
  a.download     = `passgen-history-${now.toISOString().slice(0, 10)}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`📄 Exported ${passwordHistory.length} password${passwordHistory.length > 1 ? 's' : ''}!`);
}

/* ======================================================
   Init
   ====================================================== */

function init() {
  // Apply saved theme before anything renders
  applyTheme(loadTheme());

  setLength(16);
  renderHistory();

  // Show placeholder — wait for user to click Generate
  passwordText.classList.add('placeholder');
}

init();
