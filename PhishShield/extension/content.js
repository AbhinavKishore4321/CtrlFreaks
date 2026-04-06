// PhishShield Content Script
// Highlights suspicious links with a clean overlay indicator

(function () {
  'use strict';

  const SUSPICIOUS_PATTERNS = [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,                              // IP addresses
    /(paypa1|amaz0n|g00gle|micros0ft|app1e|netfl1x|faceb00k)/i,         // Lookalike brands
    /\.(xyz|top|tk|ml|cf|gq|pw|icu|vip)\//i,                            // Suspicious TLDs
    /login.*verify|verify.*login|account.*suspended|update.*payment/i,  // Phishing phrases
  ];

  // Inject global styles once
  const styleEl = document.createElement('style');
  styleEl.textContent = `
    [data-phishshield="flagged"] {
      outline: 1.5px solid #ff3a5c !important;
      border-radius: 2px;
      position: relative;
    }
    [data-phishshield="flagged"]::after {
      content: '⚠';
      font-size: 10px;
      line-height: 1;
      color: #ff3a5c;
      background: rgba(6,8,13,.9);
      border: 1px solid rgba(255,58,92,.4);
      border-radius: 3px;
      padding: 1px 3px;
      position: absolute;
      top: -14px;
      right: 0;
      pointer-events: none;
      z-index: 999999;
    }
  `;
  document.head?.appendChild(styleEl);

  function checkLink(link) {
    const href = link.href;
    if (!href || href.startsWith('javascript') || href.startsWith('#')) return;
    if (link.dataset.phishshield) return; // already checked

    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(href)) {
        link.dataset.phishshield = 'flagged';
        link.title = '⚠ PhishShield: This link appears suspicious — proceed with caution';
        break;
      }
    }
  }

  // Initial scan
  document.querySelectorAll('a[href]').forEach(checkLink);

  // Watch for dynamically added links
  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.tagName === 'A') checkLink(node);
        node.querySelectorAll?.('a[href]').forEach(checkLink);
      }
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
