import re
import urllib.parse
import tldextract
import socket
import math
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

        # Determine verdict
        if risk_score >= 75:
            verdict = "PHISHING"
            verdict_label = "🚨 Likely Phishing"
            self.phishing_detected += 1
        elif risk_score >= 45:
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
            "risk_score": risk_score,
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

            # URL length
            url_length = len(url)

            # Count special chars
            special_chars = len(re.findall(r'[@!$%^&*#~]', url))

            # Count dots in subdomain
            subdomain_dots = subdomain.count('.') if subdomain else 0

            # HTTPS check
            has_https = url.startswith('https://')

            # Suspicious keywords in URL
            found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_url]

            # TLD check
            tld = '.' + ext.suffix if ext.suffix else ''
            is_suspicious_tld = tld in SUSPICIOUS_TLDS

            # Domain length
            domain_length = len(domain)

            # Hyphen count in domain
            hyphen_count = domain.count('-')

            # Digit count in domain
            digit_count = sum(c.isdigit() for c in domain)

            # URL entropy (randomness)
            entropy = self._calculate_entropy(domain)

            # Path depth
            path_depth = len([p for p in path.split('/') if p])

            # Query params count
            query_params = len(urllib.parse.parse_qs(query))

            # Is trusted domain
            is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)

            # Brand impersonation check
            brand_impersonation = self._check_brand_impersonation(domain, subdomain, full_url)

            # Short URL check
            is_short_url = domain in [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.io', 'rebrand.ly', 'is.gd', 'buff.ly', 'adf.ly',
                'tiny.cc', 'cutt.ly', 'shorturl.at'
            ]

            # Redirect indicators
            has_redirect = 'redirect' in full_url or 'redir' in full_url or 'url=' in full_url

            # Encoded characters
            has_encoding = '%' in url and len(re.findall(r'%[0-9a-fA-F]{2}', url)) > 2

            return {
                "domain": domain,
                "subdomain": subdomain,
                "tld": tld,
                "is_ip_address": is_ip,
                "url_length": url_length,
                "has_https": has_https,
                "special_chars_count": special_chars,
                "subdomain_depth": subdomain_dots + (1 if subdomain else 0),
                "phishing_keywords": found_keywords,
                "keyword_count": len(found_keywords),
                "is_suspicious_tld": is_suspicious_tld,
                "domain_length": domain_length,
                "hyphen_count": hyphen_count,
                "digit_count": digit_count,
                "domain_entropy": round(entropy, 3),
                "path_depth": path_depth,
                "query_params_count": query_params,
                "is_trusted_domain": is_trusted,
                "brand_impersonation": brand_impersonation,
                "is_short_url": is_short_url,
                "has_redirect": has_redirect,
                "has_encoding": has_encoding,
            }
        except Exception as e:
            return {"error": str(e)}

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count/length) * math.log2(count/length) for count in freq.values())

    def _check_brand_impersonation(self, domain: str, subdomain: str, full_url: str) -> list:
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
                  'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
                  'yahoo', 'outlook', 'office365', 'chase', 'bankofamerica',
                  'wellsfargo', 'citibank', 'ebay', 'walmart', 'coinbase']
        found = []
        for brand in brands:
            if brand in full_url:
                # Is it actually the real domain?
                real_domains = [f'{brand}.com', f'{brand}.net', f'{brand}.org']
                if not any(domain == rd for rd in real_domains):
                    found.append(brand)
        return found

    def _calculate_risk(self, features: dict, url: str, blacklist=None) -> tuple:
        score = 0
        signals = []

        if 'error' in features:
            return 50, [{"type": "error", "msg": "Could not parse URL", "weight": 0}]

        # --- Blacklist check (highest priority) ---
        if blacklist and blacklist.is_blacklisted(url):
            score += 100
            signals.append({"type": "critical", "msg": "URL found in blacklist database", "weight": 100})
            return min(score, 100), signals

        # --- IP address as domain ---
        if features.get('is_ip_address'):
            score += 35
            signals.append({"type": "danger", "msg": "Uses raw IP address instead of domain name", "weight": 35})

        # --- No HTTPS ---
        if not features.get('has_https'):
            score += 12
            signals.append({"type": "warning", "msg": "No HTTPS encryption (HTTP only)", "weight": 12})

        # --- Trusted domain bonus ---
        if features.get('is_trusted_domain'):
            score -= 30
            signals.append({"type": "safe", "msg": "Domain matches known trusted website", "weight": -30})

        # --- Brand impersonation ---
        brands = features.get('brand_impersonation', [])
        if brands:
            score += 35
            signals.append({"type": "critical", "msg": f"Impersonating brand(s): {', '.join(brands)}", "weight": 35})

        # --- Suspicious TLD ---
        if features.get('is_suspicious_tld'):
            score += 15
            signals.append({"type": "danger", "msg": f"Suspicious TLD: {features.get('tld')}", "weight": 15})

        # --- Phishing keywords ---
        kw_count = features.get('keyword_count', 0)
        if kw_count >= 4:
            score += 25
            signals.append({"type": "danger", "msg": f"{kw_count} phishing keywords detected: {', '.join(features['phishing_keywords'][:5])}", "weight": 25})
        elif kw_count >= 2:
            score += 12
            signals.append({"type": "warning", "msg": f"{kw_count} phishing keywords found: {', '.join(features['phishing_keywords'])}", "weight": 12})
        elif kw_count == 1:
            score += 5
            signals.append({"type": "info", "msg": f"Phishing keyword found: {features['phishing_keywords'][0]}", "weight": 5})

        # --- URL length ---
        length = features.get('url_length', 0)
        if length > 200:
            score += 15
            signals.append({"type": "danger", "msg": f"Very long URL ({length} chars) — typical obfuscation tactic", "weight": 15})
        elif length > 100:
            score += 7
            signals.append({"type": "warning", "msg": f"Unusually long URL ({length} chars)", "weight": 7})

        # --- Deep subdomain ---
        sub_depth = features.get('subdomain_depth', 0)
        if sub_depth >= 3:
            score += 18
            signals.append({"type": "danger", "msg": f"Deeply nested subdomain (depth {sub_depth}) — common phishing pattern", "weight": 18})
        elif sub_depth == 2:
            score += 8
            signals.append({"type": "warning", "msg": "Multiple subdomain levels detected", "weight": 8})

        # --- Hyphens in domain ---
        hyphens = features.get('hyphen_count', 0)
        if hyphens >= 3:
            score += 12
            signals.append({"type": "danger", "msg": f"Many hyphens in domain ({hyphens}) — often used to mimic legitimate sites", "weight": 12})
        elif hyphens >= 1:
            score += 4
            signals.append({"type": "info", "msg": f"Hyphens in domain name ({hyphens})", "weight": 4})

        # --- Domain entropy (randomness) ---
        entropy = features.get('domain_entropy', 0)
        if entropy > 3.8:
            score += 12
            signals.append({"type": "danger", "msg": f"High domain randomness (entropy: {entropy}) — may be auto-generated", "weight": 12})

        # --- Special characters ---
        spec = features.get('special_chars_count', 0)
        if spec >= 3:
            score += 10
            signals.append({"type": "warning", "msg": f"Suspicious special characters in URL ({spec})", "weight": 10})

        # --- Redirect indicators ---
        if features.get('has_redirect'):
            score += 10
            signals.append({"type": "warning", "msg": "URL contains redirect parameters", "weight": 10})

        # --- Encoded characters ---
        if features.get('has_encoding'):
            score += 8
            signals.append({"type": "warning", "msg": "URL contains heavy character encoding (obfuscation)", "weight": 8})

        # --- Short URL ---
        if features.get('is_short_url'):
            score += 10
            signals.append({"type": "warning", "msg": "URL shortener detected — hides true destination", "weight": 10})

        # --- Query param overload ---
        qp = features.get('query_params_count', 0)
        if qp >= 5:
            score += 8
            signals.append({"type": "warning", "msg": f"Excessive query parameters ({qp})", "weight": 8})

        # --- Digits in domain ---
        digits = features.get('digit_count', 0)
        if digits >= 4:
            score += 6
            signals.append({"type": "info", "msg": f"Many digits in domain name ({digits})", "weight": 6})

        # Clamp score
        score = max(0, min(100, score))
        return round(score), signals

    def get_stats(self) -> dict:
        return {
            "total_scans": self.scan_count,
            "phishing_detected": self.phishing_detected,
            "safe_detected": self.safe_detected,
            "suspicious": self.scan_count - self.phishing_detected - self.safe_detected
        }
