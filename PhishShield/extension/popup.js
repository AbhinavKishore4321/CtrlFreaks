document.addEventListener('DOMContentLoaded', () => {
  let currentUrl = '';

  // Get current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    currentUrl = tabs[0]?.url || '';
    const el = document.getElementById('currentUrl');
    if (currentUrl) {
      el.textContent = currentUrl;
      el.title = currentUrl;
    } else {
      el.textContent = 'No URL detected';
    }
  });

  // Scan button
  document.getElementById('scanBtn').addEventListener('click', async () => {
    const btn = document.getElementById('scanBtn');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');

    btn.disabled = true;
    loading.style.display = 'flex';
    result.classList.remove('active');
    result.style.display = 'none';

    try {
      const resp = await fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentUrl })
      });

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      renderResult(data);

    } catch (err) {
      renderError();
    }

    loading.style.display = 'none';
    btn.disabled = false;
  });

  function renderResult(data) {
    const v = (data.verdict || 'unknown').toLowerCase();
    const card = document.getElementById('verdictCard');
    const result = document.getElementById('result');

    card.className = 'verdict-card ' + v;

    const labels = {
      phishing:   '🚨 PHISHING',
      suspicious: '⚠ SUSPICIOUS',
      safe:       '✓ SAFE',
    };

    document.getElementById('verdictText').textContent = labels[v] || '? UNKNOWN';
    document.getElementById('scoreBadge').textContent = `RISK ${data.risk_score ?? 0}/100`;

    setTimeout(() => {
      document.getElementById('riskFill').style.width = (data.risk_score ?? 0) + '%';
    }, 80);

    const list = document.getElementById('signalsList');
    list.innerHTML = '';

    const order = { critical: 0, danger: 1, warning: 2, info: 3, safe: 4 };
    const sorted = (data.signals || []).sort(
      (a, b) => (order[a.type] ?? 5) - (order[b.type] ?? 5)
    );

    if (sorted.length === 0) {
      list.innerHTML = '<div class="signal-item"><div class="signal-msg" style="color:var(--text-dim)">No signals detected.</div></div>';
    } else {
      sorted.slice(0, 10).forEach(sig => {
        const item = document.createElement('div');
        item.className = 'signal-item';
        item.innerHTML = `
          <div class="sdot ${sig.type}"></div>
          <div class="signal-msg">${sig.msg}</div>
        `;
        list.appendChild(item);
      });
    }

    result.style.display = 'block';
    result.classList.add('active');
  }

  function renderError() {
    const list = document.getElementById('signalsList');
    const card = document.getElementById('verdictCard');
    const result = document.getElementById('result');

    card.className = 'verdict-card';
    card.style.display = 'none';

    list.innerHTML = `
      <div class="error-box">
        <div class="error-icon">⚠</div>
        <div>Cannot connect to PhishShield API at <strong>localhost:5000</strong>. Make sure the backend is running.</div>
      </div>
    `;

    result.style.display = 'block';
    result.classList.add('active');
  }

  // Open full app
  document.getElementById('openFullBtn').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('../../frontend/index.html') });
  });
});
