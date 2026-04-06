import re
import urllib.parse
import tldextract
import socket
import math
import requests
import os
from datetime import datetime

# Known phishing keywords
PHISHING_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account', 'verify', 'verification',
    'secure', 'security', 'update', 'confirm', 'banking', 'paypal',
    'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook',
    'instagram', 'twitter', 'support', 'helpdesk', 'alert', 'warning',
    'suspended', 'unusual', 'activity', 'validate', 'recover', 'password',
    'credential', 'billing', 'invoice', 'refund', 'prize', 'winner',
    'congratulations', 'urgent', 'immediate', 'expire', 'limited'
]

SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.link', '.gq', '.ml', '.cf', '.tk',
    '.pw', '.cc', '.ws', '.info', '.biz', '.online', '.site', '.fun',
    '.icu', '.vip', '.work', '.party', '.date', '.download', '.racing'
]

TRUSTED_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'youtube.com', 'wikipedia.org', 'stackoverflow.com', 'reddit.com',
    'netflix.com', 'spotify.com', 'adobe.com', 'dropbox.com',
    'cloudflare.com', 'anthropic.com', 'openai.com'
]

class URLScanner:
    def __init__(self):
        self.scan_count = 0
        self.phishing_detected = 0
        self.safe_detected = 0

    def scan(self, url: str, blacklist=None) -> dict:
        self.scan_count += 1

        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        features = self._extract_features(url)
        risk_score, signals = self._calculate_risk(features, url, blacklist)

        # INVERT SCORE: 100 Risk becomes 0 Trust. 0 Risk becomes 100 Trust.
        trust_score = max(0, min(100, 100 - risk_score))

        # Determine verdict based on Trust Score
        if trust_score <= 25:
            verdict = "PHISHING"
            verdict_label = "🚨 Likely Phishing"
            self.phishing_detected += 1
        elif trust_score <= 55:
            verdict = "SUSPICIOUS"
            verdict_label = "⚠️ Suspicious"
        else:
            verdict = "SAFE"
            verdict_label = "✅ Likely Safe"
            self.safe_detected += 1

        return {
            "url": url,
            "verdict": verdict,
            "verdict_label": verdict_label,
            "trust_score": trust_score,
            "risk_score": trust_score, # Keep this key so frontend doesn't break if partially updated
            "features": features,
            "signals": signals,
            "scanned_at": datetime.utcnow().isoformat() + "Z"
        }

    def _extract_features(self, url: str) -> dict:
        try:
            parsed = urllib.parse.urlparse(url)
            ext = tldextract.extract(url)
            domain = ext.registered_domain or parsed.netloc
            subdomain = ext.subdomain
            path = parsed.path
            query = parsed.query
            full_url = url.lower()

            # IP address check
            is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.netloc.split(':')[0]))

            # --- 1. DNS RESOLUTION CHECK ---
            domain_exists = False
            try:
                if domain:
                    socket.gethostbyname(domain)
                    domain_exists = True
            except socket.error:
                domain_exists = False

            # --- 2. LIVE HTTP PROBE ---
            is_live = False
            final_url = url
            if domain_exists:
                try:
                    # Timeout set to 3s to prevent the API from hanging
                    resp = requests.head(url, timeout=3, allow_redirects=True)
                    is_live = resp.status_code < 400
                    final_url = resp.url
                except requests.RequestException:
                    pass

            # Count special chars
            special_chars = len(re.findall(r'[@!$%^&*#~]', url))
            subdomain_dots = subdomain.count('.') if subdomain else 0
            
            # Feature extraction
            found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]
            tld = '.' + ext.suffix if ext.suffix else ''
            entropy = self._calculate_entropy(domain)
            is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)
            brand_impersonation = self._check_brand_impersonation(domain, subdomain, full_url)
            has_redirect = 'redirect' in full_url or 'redir' in full_url or 'url=' in full_url or (final_url != url)
            
            is_short_url = domain in [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.io', 'rebrand.ly', 'is.gd', 'buff.ly', 'adf.ly',
                'tiny.cc', 'cutt.ly', 'shorturl.at'
            ]

            return {
                "domain": domain,
                "subdomain": subdomain,
                "tld": tld,
                "domain_exists": domain_exists,
                "is_live": is_live,
                "final_url": final_url,
                "is_ip_address": is_ip,
                "url_length": len(url),
                "has_https": url.startswith('https://'),
                "special_chars_count": special_chars,
                "subdomain_depth": subdomain_dots + (1 if subdomain else 0),
                "phishing_keywords": found_keywords,
                "keyword_count": len(found_keywords),
                "is_suspicious_tld": tld in SUSPICIOUS_TLDS,
                "domain_length": len(domain),
                "hyphen_count": domain.count('-'),
                "digit_count": sum(c.isdigit() for c in domain),
                "domain_entropy": round(entropy, 3),
                "path_depth": len([p for p in path.split('/') if p]),
                "query_params_count": len(urllib.parse.parse_qs(query)),
                "is_trusted_domain": is_trusted,
                "brand_impersonation": brand_impersonation,
                "is_short_url": is_short_url,
                "has_redirect": has_redirect,
                "has_encoding": '%' in url and len(re.findall(r'%[0-9a-fA-F]{2}', url)) > 2,
            }
        except Exception as e:
            return {"error": str(e)}

    def _calculate_entropy(self, s: str) -> float:
        if not s: return 0
        freq = {c: s.count(c) for c in set(s)}
        length = len(s)
        return -sum((count/length) * math.log2(count/length) for count in freq.values())

    def _check_brand_impersonation(self, domain: str, subdomain: str, full_url: str) -> list:
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook']
        found = []
        for brand in brands:
            if brand in full_url:
                real_domains = [f'{brand}.com', f'{brand}.net', f'{brand}.org']
                if not any(domain == rd for rd in real_domains):
                    found.append(brand)
        return found

    def _check_google_safe_browsing(self, url: str) -> bool:
        """Checks URL against Google Safe Browsing API if key is present."""
        api_key = os.environ.get("SAFE_BROWSING_API_KEY")
        if not api_key: return False
        
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            resp = requests.post(api_url, json=payload, timeout=3)
            if resp.status_code == 200 and resp.json().get('matches'):
                return True
        except:
            pass
        return False

    def _calculate_risk(self, features: dict, url: str, blacklist=None) -> tuple:
        score = 0
        signals = []

        if 'error' in features:
            return 100, [{"type": "error", "msg": "Could not parse URL", "weight": -100}]

        # --- High Priority Checks ---
        if blacklist and blacklist.is_blacklisted(url):
            return 100, [{"type": "critical", "msg": "URL found in local blacklist database", "weight": -100}]

        if self._check_google_safe_browsing(url):
            return 100, [{"type": "critical", "msg": "Flagged by Google Safe Browsing API", "weight": -100}]

        # --- Active Probing Signals ---
        if not features.get('domain_exists'):
            score += 40
            signals.append({"type": "info", "msg": "Domain does not exist or DNS resolution failed (Dead Link)", "weight": -40})
        elif not features.get('is_live'):
            score += 20
            signals.append({"type": "warning", "msg": "Server is unreachable or refusing connections", "weight": -20})

        # --- Heuristics ---
        if features.get('is_ip_address'):
            score += 35
            signals.append({"type": "danger", "msg": "Uses raw IP address instead of domain name", "weight": -35})

        if not features.get('has_https'):
            score += 12
            signals.append({"type": "warning", "msg": "No HTTPS encryption (HTTP only)", "weight": -12})

        if features.get('is_trusted_domain'):
            score -= 40
            signals.append({"type": "safe", "msg": "Domain matches known trusted website", "weight": +40})

        brands = features.get('brand_impersonation', [])
        if brands:
            score += 35
            signals.append({"type": "critical", "msg": f"Impersonating brand(s): {', '.join(brands)}", "weight": -35})

        if features.get('is_suspicious_tld'):
            score += 15
            signals.append({"type": "danger", "msg": f"Suspicious TLD: {features.get('tld')}", "weight": -15})

        kw_count = features.get('keyword_count', 0)
        if kw_count >= 4:
            score += 25
            signals.append({"type": "danger", "msg": f"{kw_count} phishing keywords detected", "weight": -25})
        elif kw_count >= 2:
            score += 12
            signals.append({"type": "warning", "msg": f"Phishing keywords found: {', '.join(features['phishing_keywords'])}", "weight": -12})

        length = features.get('url_length', 0)
        if length > 200:
            score += 15
            signals.append({"type": "danger", "msg": f"Very long URL ({length} chars) — typical obfuscation", "weight": -15})

        if features.get('subdomain_depth', 0) >= 3:
            score += 18
            signals.append({"type": "danger", "msg": "Deeply nested subdomain", "weight": -18})

        if features.get('domain_entropy', 0) > 3.8:
            score += 12
            signals.append({"type": "warning", "msg": "High domain randomness (entropy) — may be auto-generated", "weight": -12})

        if features.get('has_redirect'):
            score += 10
            signals.append({"type": "warning", "msg": "URL contains redirect parameters or actively forwards traffic", "weight": -10})

        if features.get('is_short_url'):
            score += 10
            signals.append({"type": "warning", "msg": "URL shortener detected — hides true destination", "weight": -10})

        # Clamp score between 0 and 100
        score = max(0, min(100, score))
        return round(score), signals

    def get_stats(self) -> dict:
        return {
            "total_scans": self.scan_count,
            "phishing_detected": self.phishing_detected,
            "safe_detected": self.safe_detected,
            "suspicious": self.scan_count - self.phishing_detected - self.safe_detected
        }
