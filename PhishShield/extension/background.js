// PhishShield Background Service Worker
// Auto-scans pages and updates badge on tab load

const cache = new Map();
const CACHE_TTL = 300_000; // 5 minutes

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) return;

  // Serve from cache if fresh
  const cached = cache.get(tab.url);
  if (cached && (Date.now() - cached.ts) < CACHE_TTL) {
    updateBadge(tabId, cached.verdict, cached.score);
    return;
  }

  // Show scanning indicator
  chrome.action.setBadgeText({ tabId, text: '…' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#1c2a36' });

  try {
    const resp = await fetch('http://localhost:5000/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    });

    if (!resp.ok) throw new Error('API error');

    const data = await resp.json();
    cache.set(tab.url, { verdict: data.verdict, score: data.risk_score, ts: Date.now() });
    updateBadge(tabId, data.verdict, data.risk_score);

  } catch {
    // API unavailable — clear badge silently
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});

function updateBadge(tabId, verdict, score) {
  const config = {
    PHISHING:   { color: '#ff3a5c', text: '!' },
    SUSPICIOUS: { color: '#ffcc00', text: '?' },
    SAFE:       { color: '#00ff9d', text: '✓' },
  };

  const c = config[verdict] ?? { color: '#3a5568', text: '·' };
  chrome.action.setBadgeBackgroundColor({ tabId, color: c.color });
  chrome.action.setBadgeText({ tabId, text: c.text });
}
