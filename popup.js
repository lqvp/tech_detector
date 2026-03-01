/**
 * popup.js — Sakura Theme UI for Tech Detector
 * No SSL Labs API - Browser APIs only
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  // ─── State ───
  let currentData = null;
  let currentTab = 'overview';
  let searchTerm = '';
  let filterCategory = 'all';

  // ─── Simple Category Icons (emoji only) ───
  const CATEGORY_ICONS = {
    'js-framework': '⚛️',
    'js-library': '📦',
    'css-framework': '🎨',
    'cms': '📝',
    'server': '🖥️',
    'analytics': '📊',
    'cdn': '🌐',
    'font': '🔤',
    'hosting': '☁️',
    'build': '🔧',
    'security': '🔒',
    'os': '💻'
  };

  const CATEGORY_LABELS = {
    'js-framework': 'フレームワーク',
    'js-library': 'ライブラリ',
    'css-framework': 'CSS',
    'cms': 'CMS',
    'server': 'サーバー',
    'analytics': '分析',
    'cdn': 'CDN',
    'font': 'フォント',
    'hosting': 'ホスティング',
    'build': 'ビルド',
    'security': 'セキュリティ',
    'os': 'OS'
  };

  // ─── DOM Helpers ───
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  function createEl(tag, options = {}) {
    const el = document.createElement(tag);
    if (options.className) el.className = options.className;
    if (options.textContent) el.textContent = options.textContent;
    if (options.html) el.innerHTML = options.html;
    return el;
  }

  // ─── Tab Management ───
  function initTabs() {
    $$('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        switchTab(tab);
      });
    });
  }

  function switchTab(tab) {
    currentTab = tab;
    $$('.tab-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tab));
    $$('.tab-content').forEach(content => content.classList.toggle('active', content.id === `tab-${tab}`));
    if (tab === 'tech') renderTechTab();
    else if (tab === 'security') renderSecurityTab();
    else if (tab === 'details') renderDetailsTab();
  }

  // ─── Data Fetching ───
  async function init() {
    try {
      const params = new URLSearchParams(location.search);
      let tabId, tabUrl;
      
      if (params.has('tabId') && params.has('tabUrl')) {
        tabId = Number(params.get('tabId'));
        tabUrl = params.get('tabUrl');
      } else {
        const tabs = await api.tabs.query({ active: true, currentWindow: true });
        if (!tabs[0]) return;
        tabId = tabs[0].id;
        tabUrl = tabs[0].url;
      }

      const hostname = new URL(tabUrl).hostname;
      $('#hostname').textContent = hostname;

      // Run all checks (no SSL Labs)
      const [detection, encryption, headers, cookies, pageSec, dnsSec, dnsInfo, emailAuth, vtResult] = 
        await Promise.allSettled([
          api.runtime.sendMessage({ type: 'RUN_DETECTION', tabId, url: tabUrl }),
          checkEncryption(tabId, tabUrl),
          checkSecurityHeaders(tabUrl),
          checkCookies(tabUrl),
          checkPageSecurity(tabId),
          checkDnsSecurity(tabUrl),
          checkDnsInfo(tabUrl),
          checkEmailAuth(tabUrl),
          checkVirusTotal(tabUrl)
        ]);

      currentData = {
        url: tabUrl,
        hostname,
        detection: detection.status === 'fulfilled' ? detection.value : { detections: [] },
        encryption: encryption.status === 'fulfilled' ? encryption.value : null,
        headers: headers.status === 'fulfilled' ? headers.value : null,
        cookies: cookies.status === 'fulfilled' ? cookies.value : null,
        pageSecurity: pageSec.status === 'fulfilled' ? pageSec.value : null,
        dnsSecurity: dnsSec.status === 'fulfilled' ? dnsSec.value : null,
        dnsInfo: dnsInfo.status === 'fulfilled' ? dnsInfo.value : null,
        emailAuth: emailAuth.status === 'fulfilled' ? emailAuth.value : null,
        virusTotal: vtResult.status === 'fulfilled' ? vtResult.value : null,
        timestamp: new Date()
      };

      $('#loading').hidden = true;
      renderOverview();
      initTabs();
      initSearch();
      initExport();
      $('#last-updated').textContent = new Date().toLocaleTimeString('ja-JP', {hour: '2-digit', minute:'2-digit'});
    } catch (err) {
      console.error('[Tech Detector] Init error:', err);
      $('#loading').innerHTML = '<p style="color: #ffaaa5">読み込みに失敗しました</p>';
    }
  }

  // ─── Overview Tab ───
  function renderOverview() {
    const data = currentData;
    const detections = data.detection?.detections || [];
    
    $('#tech-count').textContent = `${detections.length}件`;
    $('#stat-frameworks').textContent = countByCategory(detections, 'js-framework');
    $('#stat-cms').textContent = countByCategory(detections, 'cms');
    $('#stat-analytics').textContent = countByCategory(detections, 'analytics');
    $('#stat-security').textContent = countByCategory(detections, 'security');

    const score = calculateSecurityScore(data);
    $('#security-score').textContent = score.grade;
    $('#score-progress').style.width = `${score.percentage}%`;
    $('#score-issues').textContent = score.issues > 0 
      ? `${score.issues}個の改善ポイント` 
      : '設定は良好です';

    // Tech highlights
    const highlights = $('#tech-highlights');
    highlights.innerHTML = '';
    const important = detections.filter(d => ['js-framework', 'cms', 'server'].includes(d.category)).slice(0, 8);
    
    if (important.length === 0) {
      highlights.innerHTML = '<span class="empty-text">検出中...</span>';
    } else {
      important.forEach(tech => {
        const chip = createEl('span', { className: 'tech-chip' });
        chip.innerHTML = `${CATEGORY_ICONS[tech.category] || '•'} ${tech.name}${tech.version ? ` <span class="version">v${tech.version}</span>` : ''}`;
        highlights.appendChild(chip);
      });
    }

    // TLS
    if (data.encryption) {
      $('#tls-protocol').textContent = data.encryption.https ? 'HTTPS' : 'HTTP';
      $('#tls-version').textContent = data.encryption.tlsVersion || '-';
      $('#tls-grade').textContent = data.encryption.https ? '✓' : '✗';
    }
  }

  function countByCategory(detections, category) {
    return detections.filter(d => d.category === category).length;
  }

  function calculateSecurityScore(data) {
    let score = 100;
    let issues = 0;

    if (!data.encryption?.https) { score -= 30; issues++; }
    if (data.headers) {
      ['csp', 'xContentTypeOptions', 'xFrameOptions'].forEach(h => {
        if (!data.headers[h]) { score -= 5; issues++; }
      });
    }
    if (!data.encryption?.hsts) { score -= 10; issues++; }
    if (data.cookies?.total > 0) {
      if (data.cookies.noSecure > 0) { score -= 5; issues++; }
      if (data.cookies.noHttpOnly > 0) { score -= 5; issues++; }
    }
    if (data.pageSecurity?.mixedContent > 0) { score -= 15; issues++; }
    if (data.virusTotal?.stats?.malicious > 0) { score -= 30; issues++; }

    let grade = 'A';
    if (score < 90) grade = 'B';
    if (score < 70) grade = 'C';
    if (score < 50) grade = 'D';
    if (score < 30) grade = 'F';

    return { grade, percentage: Math.max(0, score), issues };
  }

  // ─── Tech Tab ───
  function initSearch() {
    const searchInput = $('#tech-search');
    const clearBtn = $('#clear-search');
    
    searchInput?.addEventListener('input', (e) => {
      searchTerm = e.target.value.toLowerCase();
      clearBtn.hidden = !searchTerm;
      renderTechTab();
    });

    clearBtn?.addEventListener('click', () => {
      searchTerm = '';
      searchInput.value = '';
      clearBtn.hidden = true;
      renderTechTab();
    });

    $$('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        filterCategory = btn.dataset.filter;
        $$('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        renderTechTab();
      });
    });
  }

  function renderTechTab() {
    const list = $('#tech-list');
    const detections = currentData?.detection?.detections || [];
    
    let filtered = detections;
    if (filterCategory !== 'all') filtered = filtered.filter(d => d.category === filterCategory);
    if (searchTerm) filtered = filtered.filter(d => d.name.toLowerCase().includes(searchTerm));

    if (filtered.length === 0) {
      list.innerHTML = `<div class="empty-state"><p>${searchTerm ? '見つかりません' : '検出されませんでした'}</p></div>`;
      return;
    }

    const groups = {};
    filtered.forEach(d => {
      if (!groups[d.category]) groups[d.category] = [];
      groups[d.category].push(d);
    });

    list.innerHTML = '';
    Object.entries(groups).forEach(([category, items]) => {
      const categoryEl = createEl('div', { className: 'tech-category' });
      const header = createEl('div', { 
        className: 'category-header-row',
        html: `<span class="category-name">${CATEGORY_ICONS[category] || '•'} ${CATEGORY_LABELS[category] || category}</span><span class="category-badge">${items.length}</span>`
      });
      
      const itemsContainer = createEl('div', { className: 'tech-items' });
      items.forEach(tech => {
        const row = createEl('div', { className: 'tech-row' });
        row.innerHTML = `
          <span class="tech-icon-sm">${CATEGORY_ICONS[tech.category] || '•'}</span>
          <span class="tech-name-sm">${tech.name}</span>
          ${tech.version ? `<span class="tech-version-sm">v${tech.version}</span>` : ''}
        `;
        itemsContainer.appendChild(row);
      });

      header.addEventListener('click', () => itemsContainer.hidden = !itemsContainer.hidden);
      categoryEl.appendChild(header);
      categoryEl.appendChild(itemsContainer);
      list.appendChild(categoryEl);
    });
  }

  // ─── Security Tab ───
  function renderSecurityTab() {
    const data = currentData;
    
    // Headers
    const headersList = $('#headers-list');
    if (data.headers) {
      const checks = [
        { key: 'csp', label: 'Content Security Policy' },
        { key: 'xContentTypeOptions', label: 'X-Content-Type-Options' },
        { key: 'xFrameOptions', label: 'X-Frame-Options' },
        { key: 'hsts', label: 'HSTS', value: data.encryption?.hsts },
        { key: 'referrerPolicy', label: 'Referrer-Policy' }
      ];
      
      let passCount = 0;
      headersList.innerHTML = checks.map(check => {
        const value = check.value !== undefined ? check.value : data.headers[check.key];
        const pass = !!value;
        if (pass) passCount++;
        return `<div class="check-item">
          <span class="check-icon ${pass ? 'pass' : 'fail'}">${pass ? '✓' : '✗'}</span>
          <div class="check-content">
            <div class="check-label">${check.label}</div>
            ${value ? `<div class="check-value">${value.substring(0, 40)}${value.length > 40 ? '...' : ''}</div>` : ''}
          </div>
        </div>`;
      }).join('');

      const scoreBadge = $('#headers-score');
      const percentage = Math.round((passCount / checks.length) * 100);
      scoreBadge.textContent = `${percentage}%`;
      scoreBadge.className = `badge ${percentage >= 80 ? 'badge-success' : percentage >= 50 ? 'badge-warning' : 'badge-danger'}`;
    }

    // Cookies
    const cookieSummary = $('#cookie-summary');
    if (data.cookies && data.cookies.total > 0) {
      cookieSummary.innerHTML = `
        <div class="summary-item"><span class="summary-label">合計</span><span class="summary-value">${data.cookies.total}個</span></div>
        <div class="summary-item"><span class="summary-label">Secureなし</span><span class="summary-value" style="color: ${data.cookies.noSecure > 0 ? '#ffaaa5' : '#a8e6cf'}">${data.cookies.noSecure}個</span></div>
        <div class="summary-item"><span class="summary-label">HttpOnlyなし</span><span class="summary-value" style="color: ${data.cookies.noHttpOnly > 0 ? '#ffaaa5' : '#a8e6cf'}">${data.cookies.noHttpOnly}個</span></div>
      `;
    } else {
      cookieSummary.innerHTML = '<div class="summary-item"><span class="summary-label">Cookieは設定されていません</span></div>';
    }

    // Page Security
    const pageList = $('#page-security-list');
    if (data.pageSecurity) {
      const issues = [];
      if (data.pageSecurity.mixedContent > 0) issues.push({ label: 'Mixed Content', value: data.pageSecurity.mixedContent });
      if (data.pageSecurity.noSri > 0) issues.push({ label: 'SRI未設定', value: data.pageSecurity.noSri });
      if (data.pageSecurity.unsafeLinks > 0) issues.push({ label: 'noopener未設定', value: data.pageSecurity.unsafeLinks });
      
      pageList.innerHTML = issues.length > 0 
        ? issues.map(i => `<div class="check-item"><span class="check-icon warn">!</span><div class="check-content"><div class="check-label">${i.label}</div><div class="check-value">${i.value}件</div></div></div>`).join('')
        : '<div class="check-item"><span class="check-icon pass">✓</span><div class="check-content"><div class="check-label">問題は見つかりませんでした</div></div></div>';
    }
  }

  // ─── Details Tab ───
  function renderDetailsTab() {
    const data = currentData;
    
    // DNS
    const dnsDetails = $('#dns-details');
    if (data.dnsInfo) {
      dnsDetails.innerHTML = `
        <div class="detail-item"><span class="detail-label">IPアドレス</span><span class="detail-value">${data.dnsInfo.ips?.join(', ') || '-'}</span></div>
        <div class="detail-item"><span class="detail-label">ネームサーバー</span><span class="detail-value">${data.dnsInfo.ns?.join(', ') || '-'}</span></div>
        <div class="detail-item"><span class="detail-label">逆引き</span><span class="detail-value">${data.dnsInfo.ptr || 'なし'}</span></div>
      `;
    }

    // Certificate (simplified - browser limitation)
    const certDetails = $('#cert-details');
    if (data.encryption?.https) {
      certDetails.innerHTML = `
        <div class="detail-item"><span class="detail-label">プロトコル</span><span class="detail-value">HTTPS</span></div>
        <div class="detail-item"><span class="detail-label">TLSバージョン</span><span class="detail-value">${data.encryption.tlsVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HTTPバージョン</span><span class="detail-value">${data.encryption.httpVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HSTS</span><span class="detail-value">${data.encryption.hsts ? '有効' : 'なし'}</span></div>
      `;
    } else {
      certDetails.innerHTML = '<div class="detail-item"><span class="detail-value">HTTP接続のため証明書情報はありません</span></div>';
    }

    // Email Auth
    const emailDetails = $('#email-auth-details');
    if (data.emailAuth) {
      emailDetails.innerHTML = ['spf', 'dmarc'].map(key => {
        const value = data.emailAuth[key];
        const pass = !!value;
        return `<div class="check-item"><span class="check-icon ${pass ? 'pass' : 'fail'}">${pass ? '✓' : '✗'}</span><div class="check-content"><div class="check-label">${key.toUpperCase()}</div><div class="check-value">${pass ? '設定済み' : '未設定'}</div></div></div>`;
      }).join('');
    }

    // VirusTotal
    const vtDetails = $('#vt-details');
    const vtBadge = $('#vt-badge');
    if (data.virusTotal) {
      if (data.virusTotal.noKey) {
        vtDetails.innerHTML = '<div class="detail-item"><span class="detail-value">APIキー未設定</span></div>';
        vtBadge.hidden = true;
      } else if (data.virusTotal.stats) {
        const stats = data.virusTotal.stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        vtBadge.hidden = false;
        vtBadge.textContent = malicious > 0 ? '危険' : suspicious > 0 ? '注意' : '安全';
        vtBadge.className = `badge ${malicious > 0 ? 'badge-danger' : suspicious > 0 ? 'badge-warning' : 'badge-success'}`;
        vtDetails.innerHTML = `<div class="detail-item"><span class="detail-label">検出結果</span><span class="detail-value">悪意: ${malicious} / 疑わしい: ${suspicious}</span></div>`;
      }
    } else {
      vtBadge.hidden = true;
    }
  }

  // ─── Export ───
  function initExport() {
    const modal = $('#export-modal');
    
    $('#export-btn')?.addEventListener('click', () => modal.hidden = false);
    $('.modal-close')?.addEventListener('click', () => modal.hidden = true);
    modal?.addEventListener('click', (e) => { if (e.target === modal) modal.hidden = true; });
    $('#export-json')?.addEventListener('click', () => { exportToJSON(); modal.hidden = true; });
    $('#export-csv')?.addEventListener('click', () => { exportToCSV(); modal.hidden = true; });
    $('#settings-btn')?.addEventListener('click', () => api.runtime.openOptionsPage());
    $('#refresh-btn')?.addEventListener('click', () => location.reload());
  }

  function exportToJSON() {
    if (!currentData) return;
    const blob = new Blob([JSON.stringify(currentData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = createEl('a');
    a.href = url;
    a.download = `tech-detector-${currentData.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportToCSV() {
    if (!currentData?.detection?.detections) return;
    const headers = ['Name', 'Category', 'Version'];
    const rows = currentData.detection.detections.map(d => [d.name, CATEGORY_LABELS[d.category] || d.category, d.version || '']);
    const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = createEl('a');
    a.href = url;
    a.download = `tech-detector-${currentData.hostname}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ─── Check Functions (No SSL Labs) ───
  async function checkEncryption(tabId, url) {
    const isHttps = url.startsWith('https://');
    if (!isHttps) return { https: false };

    const result = { https: true };
    try {
      const [proto, headResp] = await Promise.allSettled([
        api.scripting.executeScript({
          target: { tabId },
          func: () => {
            const e = performance.getEntriesByType('navigation');
            return e[0]?.nextHopProtocol || '';
          }
        }),
        fetch(url, { method: 'HEAD' }).catch(() => null)
      ]);

      if (proto.status === 'fulfilled') {
        const p = proto.value[0]?.result;
        result.httpVersion = { 'h2': 'HTTP/2', 'h3': 'HTTP/3', 'http/1.1': 'HTTP/1.1' }[p] || p;
        if (p === 'h3') result.tlsVersion = 'TLS 1.3';
        else if (p === 'h2') result.tlsVersion = 'TLS 1.2+';
        else result.tlsVersion = 'TLS 1.x';
      }
      if (headResp.status === 'fulfilled' && headResp.value) {
        result.hsts = headResp.value.headers.get('strict-transport-security');
      }
    } catch (e) {}
    return result;
  }

  async function checkSecurityHeaders(url) {
    try {
      const resp = await fetch(url, { method: 'HEAD' });
      return {
        csp: resp.headers.get('content-security-policy'),
        xContentTypeOptions: resp.headers.get('x-content-type-options'),
        xFrameOptions: resp.headers.get('x-frame-options'),
        xXssProtection: resp.headers.get('x-xss-protection'),
        referrerPolicy: resp.headers.get('referrer-policy'),
        permissionsPolicy: resp.headers.get('permissions-policy'),
        hsts: resp.headers.get('strict-transport-security')
      };
    } catch { return null; }
  }

  async function checkCookies(url) {
    try {
      const cookies = await api.cookies.getAll({ url });
      if (cookies.length === 0) return { total: 0 };
      return {
        total: cookies.length,
        noSecure: cookies.filter(c => !c.secure).length,
        noHttpOnly: cookies.filter(c => !c.httpOnly).length,
        noSameSite: cookies.filter(c => !c.sameSite || c.sameSite === 'unspecified').length
      };
    } catch { return null; }
  }

  async function checkPageSecurity(tabId) {
    try {
      const [result] = await api.scripting.executeScript({
        target: { tabId },
        func: () => {
          const isHttps = location.protocol === 'https:';
          let mixed = 0, noSri = 0, unsafeLinks = 0;
          
          if (isHttps) {
            document.querySelectorAll('[src],[href]').forEach(el => {
              const v = el.src || el.href;
              if (v?.startsWith('http://')) mixed++;
            });
          }
          
          document.querySelectorAll('script[src],link[rel="stylesheet"][href]').forEach(el => {
            if (el.src || el.href) {
              try {
                if (new URL(el.src || el.href).hostname !== location.hostname && !el.integrity) noSri++;
              } catch {}
            }
          });

          document.querySelectorAll('a[target="_blank"]').forEach(a => {
            if (!(a.getAttribute('rel') || '').includes('noopener')) unsafeLinks++;
          });

          return { mixedContent: mixed, noSri, unsafeLinks };
        }
      });
      return result?.result;
    } catch { return null; }
  }

  async function checkDnsSecurity(url) {
    try {
      const domain = new URL(url).hostname.replace(/^www\./, '');
      const [dns, caa] = await Promise.allSettled([
        fetch(`https://dns.google/resolve?name=${domain}&type=A`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=${domain}&type=CAA`).then(r => r.json())
      ]);
      return {
        dnssec: dns.status === 'fulfilled' && dns.value.AD === true,
        caa: caa.status === 'fulfilled' ? (caa.value.Answer || []).filter(a => a.type === 257).length : 0
      };
    } catch { return null; }
  }

  async function checkDnsInfo(url) {
    try {
      const hostname = new URL(url).hostname;
      const domain = hostname.replace(/^www\./, '');
      const [a, ns] = await Promise.allSettled([
        fetch(`https://dns.google/resolve?name=${hostname}&type=A`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=${domain}&type=NS`).then(r => r.json())
      ]);

      const ips = a.status === 'fulfilled' ? (a.value.Answer || []).filter(x => x.type === 1).map(x => x.data) : [];
      const nsList = ns.status === 'fulfilled' ? (ns.value.Answer || []).filter(x => x.type === 2).map(x => x.data.replace(/\.$/, '')) : [];

      // PTR lookup
      let ptr = null;
      if (ips.length > 0) {
        try {
          const reversed = ips[0].split('.').reverse().join('.');
          const ptrResp = await fetch(`https://dns.google/resolve?name=${reversed}.in-addr.arpa&type=PTR`);
          const ptrData = await ptrResp.json();
          if (ptrData.Answer?.length > 0) ptr = ptrData.Answer[0].data.replace(/\.$/, '');
        } catch {}
      }

      return { ips, ns: nsList, ptr };
    } catch { return null; }
  }

  async function checkEmailAuth(url) {
    try {
      const domain = new URL(url).hostname.replace(/^www\./, '');
      const [spf, dmarc] = await Promise.allSettled([
        fetch(`https://dns.google/resolve?name=${domain}&type=TXT`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`).then(r => r.json())
      ]);
      return {
        spf: spf.status === 'fulfilled' ? (spf.value.Answer || []).find(a => a.data?.includes('v=spf1'))?.data : null,
        dmarc: dmarc.status === 'fulfilled' ? (dmarc.value.Answer || []).find(a => a.data?.toUpperCase().includes('V=DMARC1'))?.data : null
      };
    } catch { return null; }
  }

  async function checkVirusTotal(url) {
    try {
      const { vtApiKey } = await api.storage.sync.get('vtApiKey');
      if (!vtApiKey) return { noKey: true };
      const id = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { 'x-apikey': vtApiKey },
        signal: AbortSignal.timeout(8000)
      });
      if (!resp.ok) return { error: true };
      const json = await resp.json();
      return { stats: json.data.attributes.last_analysis_stats };
    } catch { return null; }
  }

  // ─── Start ───
  init();
})();
