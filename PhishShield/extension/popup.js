document.addEventListener('DOMContentLoaded', () => {

    let currentUrl = '';
  
    // Get current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      currentUrl = tabs[0]?.url || '';
      document.getElementById('currentUrl').textContent = currentUrl || 'No URL';
    });
  
    // Scan button click
    document.getElementById('scanBtn').addEventListener('click', async () => {
      const btn = document.getElementById('scanBtn');
      btn.disabled = true;
  
      document.getElementById('loading').style.display = 'block';
      document.getElementById('result').classList.remove('active');
  
      try {
        const resp = await fetch('http://localhost:5000/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: currentUrl })
        });
  
        const data = await resp.json();
        renderResult(data);
  
      } catch (err) {
        document.getElementById('signalsList').innerHTML =
          '<div style="color:#ff3a5c;font-size:11px">⚠ Cannot connect to PhishShield API (localhost:5000)</div>';
  
        document.getElementById('result').classList.add('active');
      }
  
      document.getElementById('loading').style.display = 'none';
      btn.disabled = false;
    });
  
    // Render scan result
    function renderResult(data) {
      const v = (data.verdict || '').toLowerCase();
      const card = document.getElementById('verdictCard');
  
      card.className = 'verdict-card ' + v;
  
      const labels = {
        phishing: '🚨 PHISHING DETECTED',
        suspicious: '⚠️ SUSPICIOUS',
        safe: '✅ SAFE'
      };
  
      document.getElementById('verdictText').textContent = labels[v] || 'Unknown';
      document.getElementById('scoreBadge').textContent = (data.risk_score ?? 0) + '/100';
  
      // Animate risk bar
      setTimeout(() => {
        document.getElementById('riskFill').style.width = (data.risk_score ?? 0) + '%';
      }, 100);
  
      // Signals list
      const list = document.getElementById('signalsList');
      list.innerHTML = '';
  
      const order = { critical: 0, danger: 1, warning: 2, info: 3, safe: 4 };
  
      const sorted = (data.signals || []).sort(
        (a, b) => (order[a.type] ?? 5) - (order[b.type] ?? 5)
      );
  
      sorted.slice(0, 8).forEach(sig => {
        const item = document.createElement('div');
        item.className = 'signal-item';
  
        item.innerHTML = `
          <div class="sdot ${sig.type}"></div>
          <div>${sig.msg}</div>
        `;
  
        list.appendChild(item);
      });
  
      document.getElementById('result').classList.add('active');
    }
  
    // Open full web app
    function openFullApp() {
      chrome.tabs.create({
        url: chrome.runtime.getURL('../../frontend/index.html')
      });
    }
  
    // ✅ FIX: Replace inline onclick
    const openBtn = document.querySelector('.open-full');
    if (openBtn) {
      openBtn.addEventListener('click', openFullApp);
    }
  
  });