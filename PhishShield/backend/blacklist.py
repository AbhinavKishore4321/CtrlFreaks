import json
import os
import urllib.parse
import tldextract

BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), 'seed_blacklist.json')
SEED_BLACKLIST_FILE = os.path.join(os.path.dirname(__file__), 'seed_blacklist.txt')

def get_seed_blacklist() -> list:
    """Reads the initial blacklist URLs from a text file."""
    if not os.path.exists(SEED_BLACKLIST_FILE):
        print(f"⚠️ Warning: Seed file '{SEED_BLACKLIST_FILE}' not found.")
        return []
    
    with open(SEED_BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        # Strip whitespace and ignore empty lines
        return [line.strip() for line in f if line.strip()]

class BlacklistDB:
    def __init__(self):
        self.blacklist = set()
        self._load()

    def _load(self):
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, 'r') as f:
                data = json.load(f)
                self.blacklist = set(data.get('urls', []))
        else:
            # Seed with known bad URLs from the text file instead of the hardcoded list
            self.blacklist = set(get_seed_blacklist())
            self._save()

    def _save(self):
        with open(BLACKLIST_FILE, 'w') as f:
            json.dump({"urls": list(self.blacklist)}, f, indent=2)

    def _normalize(self, url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.lower().strip()

    def _extract_domain(self, url: str) -> str:
        ext = tldextract.extract(url)
        return ext.registered_domain.lower() if ext.registered_domain else ''

    def is_blacklisted(self, url: str) -> bool:
        norm = self._normalize(url)
        # Check exact URL match
        if norm in self.blacklist:
            return True
        # Check domain match
        domain = self._extract_domain(norm)
        if domain:
            for bl_url in self.blacklist:
                if self._extract_domain(bl_url) == domain:
                    return True
        return False

    def add(self, url: str):
        norm = self._normalize(url)
        self.blacklist.add(norm)
        self._save()

    def remove(self, url: str):
        norm = self._normalize(url)
        self.blacklist.discard(norm)
        self._save()

    def get_all(self) -> list:
        return sorted(list(self.blacklist))

    def count(self) -> int:
        return len(self.blacklist)
