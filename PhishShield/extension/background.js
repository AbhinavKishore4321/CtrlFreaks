// PhishShield Background Service Worker
// Auto-scans pages and sets badge color based on risk

const cache = new Map();

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) return;

  // Check cache (valid for 5 minutes)
  const cached = cache.get(tab.url);
  if (cached && (Date.now() - cached.ts) < 300000) {
    updateBadge(tabId, cached.verdict, cached.score);
    return;
  }

  try {
    const resp = await fetch('http://localhost:5000/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await resp.json();
    cache.set(tab.url, { verdict: data.verdict, score: data.risk_score, ts: Date.now() });
    updateBadge(tabId, data.verdict, data.risk_score);
  } catch {
    // API not available
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});

function updateBadge(tabId, verdict, score) {
  const colors = { PHISHING: '#ff3a5c', SUSPICIOUS: '#ffb800', SAFE: '#00ff88' };
  const labels = { PHISHING: '!', SUSPICIOUS: '?', SAFE: '✓' };

  chrome.action.setBadgeBackgroundColor({ tabId, color: colors[verdict] || '#666' });
  chrome.action.setBadgeText({ tabId, text: labels[verdict] || '' });
}
