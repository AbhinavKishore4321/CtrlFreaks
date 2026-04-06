document.addEventListener('DOMContentLoaded', () => {
    let currentUrl = '';
  
    // ── Theme persistence ──────────────────────────────────────────
    const html = document.documentElement;
  
    // Load saved theme (default: dark)
    const savedTheme = localStorage.getItem('ps_theme') || 'dark';
    html.setAttribute('data-theme', savedTheme);
  
    document.getElementById('themeToggle').addEventListener('click', () => {
      const current = html.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      localStorage.setItem('ps_theme', next);
    });
  
    // ── Current tab URL ────────────────────────────────────────────
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
  
    // ── Scan button ────────────────────────────────────────────────
    document.getElementById('scanBtn').addEventListener('click', async () => {
      const btn     = document.getElementById('scanBtn');
      const loading = document.getElementById('loading');
      const result  = document.getElementById('result');
  
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
  
      } catch {
        renderError();
      }
  
      loading.style.display = 'none';
      btn.disabled = false;
    });
  
    // ── Render scan result ─────────────────────────────────────────
    function renderResult(data) {
      const v    = (data.verdict || 'unknown').toLowerCase();
      const card = document.getElementById('verdictCard');
      const result = document.getElementById('result');
  
      card.style.display = '';
      card.className = 'verdict-card ' + v;
  
      const labels = {
        phishing:   '🚨 PHISHING',
        suspicious: '⚠ SUSPICIOUS',
        safe:       '✓ SAFE',
      };
  
      document.getElementById('verdictText').textContent = labels[v] || '? UNKNOWN';
      document.getElementById('scoreBadge').textContent  = `RISK ${data.risk_score ?? 0}/100`;
  
      // Animate risk bar
      const fill = document.getElementById('riskFill');
      fill.style.width = '0';
      setTimeout(() => { fill.style.width = (data.risk_score ?? 0) + '%'; }, 80);
  
      // Signals
      const list  = document.getElementById('signalsList');
      list.innerHTML = '';
  
      const order  = { critical: 0, danger: 1, warning: 2, info: 3, safe: 4 };
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
  
    // ── Render error state ─────────────────────────────────────────
    function renderError() {
      const card   = document.getElementById('verdictCard');
      const list   = document.getElementById('signalsList');
      const result = document.getElementById('result');
  
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
  
    // ── Open full app ──────────────────────────────────────────────
    document.getElementById('openFullBtn').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('../../frontend/index.html') });
    });
  });
  