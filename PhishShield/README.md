# 🛡️ PhishShield — URL Phishing Detection Tool

> **Real-time phishing URL detection powered by heuristic analysis and ML-inspired scoring.**

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip
- Modern web browser

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the API Server

```bash
cd backend
python app.py
```

API will be live at: `http://localhost:5000`

### 3. Open the Frontend

Open `frontend/index.html` in your browser — no build step required!

---

## 🗂️ Project Structure

```
phishshield/
├── backend/
│   ├── app.py           # Flask REST API
│   ├── scanner.py       # Core URL scanner & risk engine
│   ├── blacklist.py     # Blacklist database module
│   ├── blacklist.json   # Persisted blacklist (auto-generated)
│   └── requirements.txt
│
├── frontend/
│   └── index.html       # Single-file web app (no build needed)
│
└── extension/
    ├── manifest.json    # Chrome extension manifest (v3)
    ├── popup.html       # Extension popup UI
    ├── background.js    # Auto-scan service worker
    └── content.js       # Page link analyzer
```

---

## 🔌 API Reference

### `POST /scan`
Scan a URL for phishing indicators.

**Request:**
```json
{ "url": "https://suspicious-site.xyz/login" }
```

**Response:**
```json
{
  "url": "https://suspicious-site.xyz/login",
  "verdict": "PHISHING",
  "verdict_label": "🚨 Likely Phishing",
  "risk_score": 82,
  "scan_time_ms": 12.5,
  "signals": [
    { "type": "danger", "msg": "Suspicious TLD: .xyz", "weight": 15 },
    { "type": "warning", "msg": "2 phishing keywords found: login, verify", "weight": 12 }
  ],
  "features": {
    "domain": "suspicious-site.xyz",
    "has_https": false,
    "url_length": 38,
    ...
  },
  "scanned_at": "2024-01-15T12:00:00Z"
}
```

### `GET /stats`
Get scan statistics.

### `POST /blacklist/add`
Add a URL to the blacklist.
```json
{ "url": "http://malicious.xyz" }
```

### `GET /blacklist/list`
List all blacklisted URLs.

### `GET /health`
Health check endpoint.

---

## 🧠 How It Works

PhishShield uses **20+ heuristic signals** to calculate a risk score (0–100):

| Signal | Weight | Description |
|--------|--------|-------------|
| Blacklist match | +100 | URL/domain in known bad list |
| Brand impersonation | +35 | Mimics PayPal, Google, etc. |
| IP address as host | +25 | Raw IP instead of domain name |
| Phishing keywords (4+) | +25 | login, verify, account, etc. |
| Deep subdomain | +18 | 3+ levels deep |
| Suspicious TLD | +15 | .xyz, .tk, .ml, .cf, etc. |
| No HTTPS | +12 | HTTP only |
| Very long URL (200+) | +15 | Obfuscation tactic |
| High entropy domain | +12 | Random-looking domain |
| URL shortener | +10 | Hides true destination |
| Redirect param | +10 | Contains redirect indicators |
| Trusted domain | -30 | Known legitimate site |

**Risk Score → Verdict:**
- 0–44: ✅ **SAFE**
- 45–74: ⚠️ **SUSPICIOUS**
- 75–100: 🚨 **PHISHING**

---

## 🔒 Browser Extension Setup

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right)
3. Click **Load unpacked**
4. Select the `extension/` folder

**Features:**
- 🟢 Badge indicator on every page (✓ / ? / !)
- Click popup to scan current page
- Automatically highlights suspicious links on any webpage
- Caches results for 5 minutes

---

## 🗄️ Blacklist Database

The blacklist is stored in `backend/blacklist.json` and pre-seeded with known phishing URLs. It supports:

- **Exact URL matching**
- **Domain-level matching** (blocks all paths on a flagged domain)
- **Persistent storage** across restarts
- **REST API** for adding/listing entries

---

## ⚙️ Engineering Challenges & Solutions

| Challenge | Solution |
|-----------|----------|
| False positives | Trusted domain allowlist with -30 score bonus |
| Short URLs | Detected by known shortener domain list |
| Brand spoofing | Pattern matching against 20+ major brands |
| IP-based URLs | Regex detection, +25 score penalty |
| Encoded URLs | Detects heavy `%XX` encoding as obfuscation |
| Performance | Feature extraction in <15ms, no external API calls |

---

## 🔮 Bonus Features Implemented

- ✅ **Blacklist DB** with domain-level matching
- ✅ **Browser Extension** (Chrome MV3) with auto-scanning
- ✅ **Link analyzer** content script that highlights suspicious links on any page
- ✅ **Persistent stats** (total scans, threats found, safe URLs)
- ✅ **Report export** (copy scan report to clipboard)

---

## 📊 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, Flask-CORS |
| URL Analysis | tldextract, urllib, re, math |
| Frontend | Vanilla HTML/CSS/JS (zero dependencies) |
| Extension | Chrome MV3 (Manifest v3) |
| Storage | JSON file (blacklist), in-memory stats |

---

## 🧪 Test URLs

| URL | Expected |
|-----|----------|
| `https://google.com` | ✅ SAFE |
| `http://paypa1-secure.verify-account.xyz/login` | 🚨 PHISHING |
| `http://192.168.1.1/admin` | 🚨 PHISHING |
| `https://bit.ly/3abc` | ⚠️ SUSPICIOUS |
| `http://microsoft-support-alert.tk` | 🚨 PHISHING |
| `https://github.com` | ✅ SAFE |

---

## 📜 License
MIT — Build freely, share openly.
