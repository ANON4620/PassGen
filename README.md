# 🔐 PassGen — Secure Password Generator

PassGen is a modern, privacy-first password generator that runs entirely in the browser.  
No data is ever sent to any server — everything stays on your device.

---

## ✨ Features

- 🔐 **Cryptographically Secure** — Uses Web Crypto API (`crypto.getRandomValues`) for true randomness  
- ⚙️ **Fully Customizable** — Length (4–128), uppercase, lowercase, numbers, symbols  
- 🚫 **Exclude Ambiguous Characters** — Avoid O/0/l/I/1 confusion  
- 📊 **Entropy-Based Strength Meter** — Real-time password strength calculation  
- ⏱️ **Crack Time Estimate** — Based on brute-force assumptions (10B guesses/sec)  
- 📋 **One-Click Copy** — Instant clipboard copy with feedback  
- 🕒 **Session History** — Stores last 10 generated passwords  
- 📱 **Fully Responsive UI** — Works across mobile, tablet, and desktop  
- ♿ **Accessible Design** — Keyboard navigation + ARIA support  

---

## 📸 Preview

<p align="center">
  <img src="https://github.com/user-attachments/assets/01293244-2667-49f9-a902-71175b2141b2" />
</p>

---

## 🧠 How It Works

PassGen generates secure passwords using the Web Crypto API:

```js
crypto.getRandomValues()
