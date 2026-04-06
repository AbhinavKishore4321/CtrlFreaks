// PhishShield Content Script
// Adds warning overlays on links that look suspicious

(function () {
  'use strict';

  const SUSPICIOUS_PATTERNS = [
    /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // IP addresses
    /(paypa1|amaz0n|g00gle|micros0ft|app1e|netfl1x|faceb00k)/i, // Lookalike brands
    /\.(xyz|top|tk|ml|cf|gq|pw|icu|vip)\//i,  // Suspicious TLDs
    /login.*verify|verify.*login|account.*suspended/i,
  ];

  function checkLink(link) {
    const href = link.href;
    if (!href || href.startsWith('javascript') || href.startsWith('#')) return;

    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(href)) {
        link.style.outline = '2px solid #ff3a5c';
        link.title = '⚠️ PhishShield: This link appears suspicious';
        link.dataset.phishshield = 'flagged';
        break;
      }
    }
  }

  // Scan all links on page load
  document.querySelectorAll('a[href]').forEach(checkLink);

  // Observe dynamically added links
  const observer = new MutationObserver(mutations => {
    mutations.forEach(m => {
      m.addedNodes.forEach(node => {
        if (node.nodeType === 1) {
          if (node.tagName === 'A') checkLink(node);
          node.querySelectorAll?.('a[href]').forEach(checkLink);
        }
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();
