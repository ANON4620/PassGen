# PassGen — Secure Password Generator

A modern, privacy-first password generator that runs entirely in the browser. No data is ever sent to any server.

## ✨ Features

- 🔐 **Cryptographically Secure** — Uses the Web Crypto API (`crypto.getRandomValues`) for true randomness
- ⚙️ **Fully Customizable** — Choose length (4–128), uppercase, lowercase, numbers, symbols
- 🚫 **Exclude Ambiguous Chars** — Avoid confusing characters like O, 0, l, I, 1
- 📊 **Strength Meter** — Real-time entropy-based password strength indicator
- ⏱️ **Crack Time Estimate** — Rough time-to-crack at 10 billion guesses/second
- 📋 **One-Click Copy** — Copy to clipboard instantly
- 🕒 **Session History** — Keep track of your last 10 generated passwords
- 📱 **Fully Responsive** — Works on desktop, tablet, and mobile
- ♿ **Accessible** — ARIA labels, keyboard navigation, focus indicators

```

## 📁 Project Structure

```
PassGen/
├── index.html     # Main HTML — structure & layout
├── style.css      # Premium dark glassmorphism UI
├── app.js         # All logic (generation, crypto, clipboard)
├── vercel.json    # Vercel deployment config
└── README.md      # This file
```

## 🔒 Security Notes

- All passwords are generated using `crypto.getRandomValues()` — cryptographically secure
- Rejection sampling is used to avoid modulo bias
- No network requests are made after page load
- No cookies, no tracking, no analytics
- All data stays in your browser session only


<img width="1895" height="940" alt="image" src="https://github.com/user-attachments/assets/01293244-2667-49f9-a902-71175b2141b2" />
