/**
 * Tech Detector Enhanced - Popup
 * 整理版: シンプルで確実なデータフロー
 */
(() => {
  'use strict';
  const api = typeof browser !== 'undefined' ? browser : chrome;

  // === 状態管理 ===
  const state = {
    data: null,
    tab: 'overview',
    search: '',
    filter: 'all',
    history: []
  };

  // === 定数 ===
  const ICONS = {
    'js-framework': '⚛️', 'js-library': '📦', 'css-framework': '🎨',
    'cms': '📝', 'server': '🖥️', 'analytics': '📊',
    'cdn': '🌐', 'font': '🔤', 'hosting': '☁️',
    'build': '🔧', 'security': '🔒', 'os': '💻'
  };

  const LABELS = {
    'js-framework': 'フレームワーク', 'js-library': 'ライブラリ',
    'css-framework': 'CSS', 'cms': 'CMS', 'server': 'サーバー',
    'analytics': 'アナリティクス', 'cdn': 'CDN', 'font': 'フォント',
    'hosting': 'ホスティング', 'build': 'ビルド',
    'security': 'セキュリティ', 'os': 'OS'
  };

  // === DOM ヘルパー ===
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);
  const h = (s) => s?.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);

  // === 初期化 ===
  async function init() {
    try {
      // URLパラメータ取得
      const params = new URLSearchParams(location.search);
      let tabId = params.has('tabId') ? Number(params.get('tabId')) : null;
      let tabUrl = params.get('tabUrl');

      // フォールバック: アクティブタブ
      if (!tabId || !tabUrl) {
        const [tab] = await api.tabs.query({ active: true, currentWindow: true });
        if (!tab) return showError('タブ情報を取得できません');
        tabId = tab.id;
        tabUrl = tab.url;
      }

      const hostname = new URL(tabUrl).hostname;
      $('#hostname').textContent = hostname;

      // 履歴読み込み
      await loadHistory();

      // データ収集（並列実行）
      showLoading(true);
      
      const [
        detection, encryption, headers, cookies, pageSec,
        dnsInfo, emailAuth, vtResult, vitals, whois, ogp, links
      ] = await Promise.all([
        runDetection(tabId, tabUrl),
        getEncryption(tabId, tabUrl),
        getHeaders(tabUrl),
        getCookies(tabUrl),
        getPageSecurity(tabId),
        getDnsInfo(tabUrl),
        getEmailAuth(tabUrl),
        getVirusTotal(tabUrl),
        getWebVitals(tabId),
        getWhois(hostname),
        getOGP(tabId),
        getLinks(tabId)
      ]);

      // 状態保存
      state.data = {
        url: tabUrl,
        hostname,
        detection,
        encryption,
        headers,
        cookies,
        pageSecurity: pageSec,
        dnsInfo,
        emailAuth,
        virusTotal: vtResult,
        vitals,
        whois,
        ogp,
        links,
        timestamp: Date.now()
      };

      // 履歴保存
      await saveHistory(state.data);

      // UI更新
      showLoading(false);
      updateOverview();
      initTabs();
      initSearch();
      initExport();
      
      $('#last-updated').textContent = new Date().toLocaleTimeString('ja-JP', {hour: '2-digit', minute:'2-digit'});

    } catch (err) {
      console.error('Init error:', err);
      showError('読み込みに失敗しました: ' + err.message);
    }
  }

  // === データ収集関数 ===

  async function runDetection(tabId, url) {
    try {
      return await api.runtime.sendMessage({ type: 'RUN_DETECTION', tabId, url });
    } catch {
      return { detections: [] };
    }
  }

  async function getEncryption(tabId, url) {
    if (!url.startsWith('https://')) return { https: false };
    
    try {
      const [{ result: proto }] = await api.scripting.executeScript({
        target: { tabId },
        func: () => performance.getEntriesByType('navigation')[0]?.nextHopProtocol
      });

      const result = { https: true, protocol: proto };
      
      if (proto === 'h3') result.tlsVersion = 'TLS 1.3';
      else if (proto === 'h2') result.tlsVersion = 'TLS 1.2';
      else if (proto === 'http/1.1') result.tlsVersion = 'TLS 1.0-1.2';
      
      result.httpVersion = { h2: 'HTTP/2', h3: 'HTTP/3', 'http/1.1': 'HTTP/1.1' }[proto] || proto;

      // HSTS取得
      try {
        const resp = await fetch(url, { method: 'HEAD' });
        result.hsts = resp.headers.get('strict-transport-security');
      } catch {}

      return result;
    } catch {
      return { https: true };
    }
  }

  async function getHeaders(url) {
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
    } catch {
      return {};
    }
  }

  async function getCookies(url) {
    try {
      const cookies = await api.cookies.getAll({ url });
      return {
        total: cookies.length,
        noSecure: cookies.filter(c => !c.secure).length,
        noHttpOnly: cookies.filter(c => !c.httpOnly).length
      };
    } catch {
      return { total: 0 };
    }
  }

  async function getPageSecurity(tabId) {
    try {
      const [{ result }] = await api.scripting.executeScript({
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
            try {
              const u = new URL(el.src || el.href, location.href);
              if (u.hostname !== location.hostname && !el.integrity) noSri++;
            } catch {}
          });

          document.querySelectorAll('a[target="_blank"]').forEach(a => {
            if (!(a.getAttribute('rel') || '').includes('noopener')) unsafeLinks++;
          });

          return { mixedContent: mixed, noSri, unsafeLinks };
        }
      });
      return result;
    } catch {
      return {};
    }
  }

  async function getDnsInfo(url) {
    try {
      const hostname = new URL(url).hostname;
      const domain = hostname.replace(/^www\./, '');
      
      const [aResp, nsResp] = await Promise.all([
        fetch(`https://dns.google/resolve?name=${hostname}&type=A`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=${domain}&type=NS`).then(r => r.json())
      ]);

      const ips = aResp.Answer?.filter(r => r.type === 1).map(r => r.data) || [];
      const ns = nsResp.Answer?.filter(r => r.type === 2).map(r => r.data.replace(/\.$/, '')) || [];

      // PTR（逆引き）
      let ptr = null;
      if (ips[0]) {
        try {
          const reversed = ips[0].split('.').reverse().join('.');
          const ptrResp = await fetch(`https://dns.google/resolve?name=${reversed}.in-addr.arpa&type=PTR`);
          const ptrData = await ptrResp.json();
          ptr = ptrData.Answer?.[0]?.data.replace(/\.$/, '');
        } catch {}
      }

      return { ips, ns, ptr };
    } catch {
      return { ips: [], ns: [], ptr: null };
    }
  }

  async function getEmailAuth(url) {
    try {
      const domain = new URL(url).hostname.replace(/^www\./, '');
      const [spfResp, dmarcResp] = await Promise.all([
        fetch(`https://dns.google/resolve?name=${domain}&type=TXT`).then(r => r.json()),
        fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`).then(r => r.json())
      ]);

      const spf = spfResp.Answer?.find(r => r.data?.includes('v=spf1'))?.data;
      const dmarc = dmarcResp.Answer?.find(r => r.data?.toUpperCase().includes('V=DMARC1'))?.data;

      return { spf, dmarc };
    } catch {
      return {};
    }
  }

  async function getVirusTotal(url) {
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
    } catch {
      return null;
    }
  }

  async function getWebVitals(tabId) {
    try {
      const [{ result }] = await api.scripting.executeScript({
        target: { tabId },
        func: () => {
          const nav = performance.getEntriesByType('navigation')[0];
          return {
            lcp: nav?.loadEventEnd ? nav.loadEventEnd - nav.startTime : null,
            ttfb: nav?.responseStart ? nav.responseStart - nav.startTime : null,
            pageSize: nav?.transferSize,
            requests: performance.getEntriesByType('resource').length,
            domElements: document.getElementsByTagName('*').length
          };
        }
      });
      return result;
    } catch {
      return {};
    }
  }

  async function getWhois(hostname) {
    // まずIPを取得
    let ip = null;
    try {
      const dnsResp = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`);
      const dnsData = await dnsResp.json();
      ip = dnsData.Answer?.find(r => r.type === 1)?.data;
    } catch {}

    if (!ip) return { ip: null };

    // ipinfo.ioでIP情報を取得
    try {
      const resp = await fetch(`https://ipinfo.io/${ip}/json`, {
        signal: AbortSignal.timeout(5000)
      });
      
      if (!resp.ok) return { ip };
      
      const data = await resp.json();

      return {
        ip,
        country: data.country,
        region: data.region,
        city: data.city,
        isp: data.org,
        org: data.org,
        asn: data.asn?.asn
      };
    } catch (err) {
      console.warn('[Whois] Failed:', err);
      return { ip };
    }
  }

  async function getOGP(tabId) {
    try {
      const [{ result }] = await api.scripting.executeScript({
        target: { tabId },
        func: () => {
          const getMeta = (name) => {
            const el = document.querySelector(`meta[property="og:${name}"],meta[name="${name}"],meta[name="twitter:${name}"]`);
            return el?.content;
          };
          
          const favicon = document.querySelector('link[rel~="icon"]')?.href;
          
          return {
            title: getMeta('title') || document.title,
            description: getMeta('description') || '',
            image: getMeta('image'),
            favicon: favicon || '/favicon.ico'
          };
        }
      });
      return result;
    } catch {
      return {};
    }
  }

  async function getLinks(tabId) {
    try {
      const [{ result }] = await api.scripting.executeScript({
        target: { tabId },
        func: () => {
          const links = document.querySelectorAll('a[href]');
          const ownHost = location.hostname;
          let external = 0, internal = 0;
          
          links.forEach(a => {
            try {
              const url = new URL(a.href);
              if (url.hostname === ownHost || url.hostname.endsWith('.' + ownHost)) internal++;
              else external++;
            } catch {}
          });
          
          return { total: links.length, external, internal };
        }
      });
      return result;
    } catch {
      return { total: 0, external: 0, internal: 0 };
    }
  }

  // === 履歴管理 ===

  async function loadHistory() {
    try {
      const { detection_history } = await api.storage.local.get('detection_history');
      state.history = detection_history || [];
    } catch {
      state.history = [];
    }
  }

  async function saveHistory(data) {
    try {
      // 現在の履歴を取得
      const { detection_history = [] } = await api.storage.local.get('detection_history');
      
      // 同じホスト名の古いエントリを削除
      const filtered = detection_history.filter(h => h.hostname !== data.hostname);
      
      // スコア計算
      const score = calcScore(data).percent;
      
      // 新しいエントリを追加
      filtered.unshift({
        hostname: data.hostname,
        url: data.url,
        timestamp: Date.now(),
        detectionCount: data.detection?.detections?.length || 0,
        score: score
      });
      
      // 最大20件に制限
      state.history = filtered.slice(0, 20);
      
      await api.storage.local.set({ detection_history: state.history });
      console.log('[Popup] History saved:', data.hostname, 'score:', score);
    } catch (err) {
      console.error('History save failed:', err);
    }
  }

  // === UI更新 ===

  function updateOverview() {
    const d = state.data;
    const detections = d.detection?.detections || [];
    
    // カウント
    $('#tech-count').textContent = detections.length + '件';
    $('#stat-frameworks').textContent = detections.filter(x => x.category === 'js-framework').length;
    $('#stat-cms').textContent = detections.filter(x => x.category === 'cms').length;
    $('#stat-analytics').textContent = detections.filter(x => x.category === 'analytics').length;
    $('#stat-security').textContent = detections.filter(x => x.category === 'security').length;

    // スコア
    const score = calcScore(d);
    $('#security-score').textContent = score.grade;
    $('#score-progress').style.width = score.percent + '%';
    $('#score-issues').textContent = score.issues > 0 
      ? score.issues + '個の改善が推奨されます'
      : 'セキュリティ設定は良好です';

    // 技術ハイライト
    const highlights = $('#tech-highlights');
    const important = detections.filter(x => ['js-framework', 'cms', 'server'].includes(x.category)).slice(0, 8);
    
    if (important.length === 0) {
      highlights.innerHTML = '<span class="empty-text">技術を検出中...</span>';
    } else {
      highlights.innerHTML = important.map(t => 
        `<span class="tech-chip">${ICONS[t.category] || '•'} ${h(t.name)}${t.version ? ` <span class="version">v${h(t.version)}</span>` : ''}</span>`
      ).join('');
    }

    // TLS
    if (d.encryption) {
      $('#tls-protocol').textContent = d.encryption.https ? 'HTTPS対応' : 'HTTP';
      $('#tls-version').textContent = d.encryption.tlsVersion || '不明';
      $('#tls-grade').textContent = d.encryption.httpVersion || '-';
    }

    // Vitalsプレビュー
    if (d.vitals) {
      $('#vitals-preview').innerHTML = `
        <div class="summary-item">
          <span class="summary-label">LCP</span>
          <span class="summary-value">${d.vitals.lcp ? Math.round(d.vitals.lcp) + 'ms' : '-'}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">CLS</span>
          <span class="summary-value">${d.vitals.cls?.toFixed(3) || '-'}</span>
        </div>
      `;
    }
  }

  function calcScore(d) {
    let score = 100, issues = 0;
    
    if (!d.encryption?.https) { score -= 30; issues++; }
    if (!d.headers?.csp) { score -= 5; issues++; }
    if (!d.headers?.xContentTypeOptions) { score -= 5; issues++; }
    if (!d.headers?.xFrameOptions) { score -= 5; issues++; }
    if (!d.encryption?.hsts) { score -= 10; issues++; }
    if (d.cookies?.noSecure > 0) { score -= 5; issues++; }
    if (d.cookies?.noHttpOnly > 0) { score -= 5; issues++; }
    if (d.pageSecurity?.mixedContent > 0) { score -= 15; issues++; }
    if (d.virusTotal?.stats?.malicious > 0) { score -= 30; issues++; }

    let grade = 'A';
    if (score < 90) grade = 'B';
    if (score < 70) grade = 'C';
    if (score < 50) grade = 'D';
    if (score < 30) grade = 'F';
    
    return { grade, percent: Math.max(0, score), issues };
  }

  // === タブ管理 ===

  function initTabs() {
    $$('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.tab = btn.dataset.tab;
        $$('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
        $$('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + state.tab));
        
        if (state.tab === 'tech') renderTechTab();
        else if (state.tab === 'security') renderSecurityTab();
        else if (state.tab === 'details') renderDetailsTab();
        else if (state.tab === 'performance') renderPerformanceTab();
        else if (state.tab === 'history') renderHistoryTab();
      });
    });
  }

  function renderTechTab() {
    const list = $('#tech-list');
    const detections = state.data.detection?.detections || [];
    
    let filtered = detections;
    if (state.filter !== 'all') filtered = filtered.filter(x => x.category === state.filter);
    if (state.search) filtered = filtered.filter(x => x.name.toLowerCase().includes(state.search));

    if (filtered.length === 0) {
      list.innerHTML = `<div class="empty-state"><p>${state.search ? '見つかりませんでした' : '検出された技術はありません'}</p></div>`;
      return;
    }

    // カテゴリでグループ化
    const groups = {};
    filtered.forEach(d => {
      if (!groups[d.category]) groups[d.category] = [];
      groups[d.category].push(d);
    });

    list.innerHTML = Object.entries(groups).map(([cat, items]) => `
      <div class="tech-category">
        <div class="category-header-row" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden">
          <span class="category-name">${ICONS[cat] || '•'} ${h(LABELS[cat] || cat)}</span>
          <span class="category-badge">${items.length}件</span>
        </div>
        <div class="tech-items">
          ${items.map(t => `
            <div class="tech-row">
              <span class="tech-icon-sm">${ICONS[t.category] || '•'}</span>
              <span class="tech-name-sm">${h(t.name)}</span>
              ${t.version ? `<span class="tech-version-sm">v${h(t.version)}</span>` : ''}
            </div>
          `).join('')}
        </div>
      </div>
    `).join('');
  }

  function renderSecurityTab() {
    const d = state.data;
    
    // ヘッダー
    const checks = [
      { key: 'csp', label: 'Content Security Policy' },
      { key: 'xContentTypeOptions', label: 'X-Content-Type-Options' },
      { key: 'xFrameOptions', label: 'X-Frame-Options' },
      { key: 'hsts', label: 'HSTS', val: d.encryption?.hsts },
      { key: 'referrerPolicy', label: 'Referrer-Policy' }
    ];
    
    let passed = 0;
    $('#headers-list').innerHTML = checks.map(c => {
      const val = c.val !== undefined ? c.val : d.headers?.[c.key];
      const ok = !!val;
      if (ok) passed++;
      return `<div class="check-item">
        <span class="check-icon ${ok ? 'pass' : 'fail'}">${ok ? '✓' : '✗'}</span>
        <div class="check-content">
          <div class="check-label">${c.label}</div>
          ${val ? `<div class="check-value">${h(val.substring(0, 40))}${val.length > 40 ? '...' : ''}</div>` : ''}
        </div>
      </div>`;
    }).join('');

    const pct = Math.round((passed / checks.length) * 100);
    const badge = $('#headers-score');
    badge.textContent = pct + '%';
    badge.className = 'badge ' + (pct >= 80 ? 'badge-success' : pct >= 50 ? 'badge-warning' : 'badge-danger');

    // Cookie
    if (d.cookies?.total > 0) {
      $('#cookie-summary').innerHTML = `
        <div class="summary-item"><span class="summary-label">合計</span><span class="summary-value">${d.cookies.total}個</span></div>
        <div class="summary-item"><span class="summary-label">Secure属性なし</span><span class="summary-value" style="color:${d.cookies.noSecure>0?'#ffaaa5':'#a8e6cf'}">${d.cookies.noSecure}個</span></div>
        <div class="summary-item"><span class="summary-label">HttpOnly属性なし</span><span class="summary-value" style="color:${d.cookies.noHttpOnly>0?'#ffaaa5':'#a8e6cf'}">${d.cookies.noHttpOnly}個</span></div>
      `;
    } else {
      $('#cookie-summary').innerHTML = '<div class="summary-item"><span class="summary-label">Cookieは設定されていません</span></div>';
    }

    // ページ診断
    const issues = [];
    if (d.pageSecurity?.mixedContent > 0) issues.push({ label: 'Mixed Content', val: d.pageSecurity.mixedContent });
    if (d.pageSecurity?.noSri > 0) issues.push({ label: 'SRI未設定', val: d.pageSecurity.noSri });
    if (d.pageSecurity?.unsafeLinks > 0) issues.push({ label: 'noopener未設定', val: d.pageSecurity.unsafeLinks });
    
    $('#page-security-list').innerHTML = issues.length > 0
      ? issues.map(i => `<div class="check-item"><span class="check-icon warn">!</span><div class="check-content"><div class="check-label">${i.label}</div><div class="check-value">${i.val}件検出</div></div></div>`).join('')
      : '<div class="check-item"><span class="check-icon pass">✓</span><div class="check-content"><div class="check-label">重大な問題は検出されませんでした</div></div></div>';
  }

  function renderDetailsTab() {
    const d = state.data;
    
    // OGP
    if (d.ogp?.title) {
      $('#ogp-preview').innerHTML = `
        <div style="display:flex;gap:12px;align-items:flex-start">
          ${d.ogp.image ? `<img src="${h(d.ogp.image)}" style="width:60px;height:60px;object-fit:cover;border-radius:8px" onerror="this.style.display='none'">` : ''}
          <div style="flex:1;min-width:0">
            <div style="font-weight:600;font-size:13px;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h(d.ogp.title)}</div>
            <div style="font-size:11px;color:var(--text-muted);overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${h(d.ogp.description)}</div>
          </div>
        </div>
      `;
    }

    // DNS
    $('#dns-details').innerHTML = `
      <div class="detail-item"><span class="detail-label">IPアドレス</span><span class="detail-value">${d.dnsInfo?.ips?.join(', ') || '取得できません'}</span></div>
      <div class="detail-item"><span class="detail-label">ネームサーバー</span><span class="detail-value">${d.dnsInfo?.ns?.join(', ') || '取得できません'}</span></div>
      <div class="detail-item"><span class="detail-label">逆引き（PTR）</span><span class="detail-value">${d.dnsInfo?.ptr || '設定されていません'}</span></div>
    `;

    // Whois
    if (d.whois?.ip) {
      $('#whois-details').innerHTML = `
        <div class="detail-item"><span class="detail-label">IPアドレス</span><span class="detail-value">${h(d.whois.ip)}</span></div>
        <div class="detail-item"><span class="detail-label">国</span><span class="detail-value">${d.whois.country || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">地域</span><span class="detail-value">${d.whois.region || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">都市</span><span class="detail-value">${d.whois.city || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">ISP/組織</span><span class="detail-value">${d.whois.org || '取得できません'}</span></div>
      `;
    } else {
      $('#whois-details').innerHTML = '<div class="detail-item"><span class="detail-value">ドメイン情報を取得できませんでした</span></div>';
    }

    // 証明書
    if (d.encryption?.https) {
      $('#cert-details').innerHTML = `
        <div class="detail-item"><span class="detail-label">プロトコル</span><span class="detail-value">HTTPS（暗号化通信）</span></div>
        <div class="detail-item"><span class="detail-label">TLSバージョン</span><span class="detail-value">${d.encryption.tlsVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HTTPバージョン</span><span class="detail-value">${d.encryption.httpVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HSTS</span><span class="detail-value">${d.encryption.hsts ? '有効' : '無効'}</span></div>
      `;
    } else {
      $('#cert-details').innerHTML = '<div class="detail-item"><span class="detail-value">HTTP接続のため、証明書情報はありません</span></div>';
    }

    // メール認証
    $('#email-auth-details').innerHTML = ['spf', 'dmarc'].map(k => {
      const ok = !!d.emailAuth?.[k];
      return `<div class="check-item"><span class="check-icon ${ok ? 'pass' : 'fail'}">${ok ? '✓' : '✗'}</span><div class="check-content"><div class="check-label">${k.toUpperCase()}</div><div class="check-value">${ok ? '設定済み' : '未設定'}</div></div></div>`;
    }).join('');

    // VirusTotal
    const vtBadge = $('#vt-badge');
    if (d.virusTotal?.noKey) {
      $('#vt-details').innerHTML = '<div class="detail-item"><span class="detail-value">設定画面でAPIキーを設定してください</span></div>';
      vtBadge.hidden = true;
    } else if (d.virusTotal?.stats) {
      const s = d.virusTotal.stats;
      const bad = (s.malicious || 0) + (s.suspicious || 0);
      vtBadge.hidden = false;
      vtBadge.textContent = bad > 0 ? '危険' : '安全';
      vtBadge.className = 'badge ' + (bad > 0 ? 'badge-danger' : 'badge-success');
      $('#vt-details').innerHTML = `<div class="detail-item"><span class="detail-label">検出結果</span><span class="detail-value">悪意:${s.malicious||0}/疑わしい:${s.suspicious||0}/安全:${s.harmless||0}</span></div>`;
    } else {
      vtBadge.hidden = true;
    }

    // リンク統計
    $('#links-details').innerHTML = `
      <div class="summary-item"><span class="summary-label">総リンク数</span><span class="summary-value">${d.links?.total || 0}個</span></div>
      <div class="summary-item"><span class="summary-label">外部リンク</span><span class="summary-value">${d.links?.external || 0}個</span></div>
      <div class="summary-item"><span class="summary-label">内部リンク</span><span class="summary-value">${d.links?.internal || 0}個</span></div>
    `;
  }

  function renderPerformanceTab() {
    const v = state.data.vitals;
    $('#performance-content').innerHTML = `
      <div class="card">
        <h3 class="section-title">Core Web Vitals</h3>
        <div class="vitals-grid">
          <div class="vital-card">
            <span class="vital-name">LCP</span>
            <span class="vital-value">${v?.lcp ? Math.round(v.lcp) + 'ms' : '-'}</span>
            <span class="vital-desc">最大コンテンツ表示時間</span>
          </div>
          <div class="vital-card">
            <span class="vital-name">TTFB</span>
            <span class="vital-value">${v?.ttfb ? Math.round(v.ttfb) + 'ms' : '-'}</span>
            <span class="vital-desc">サーバー応答時間</span>
          </div>
          <div class="vital-card">
            <span class="vital-name">ページサイズ</span>
            <span class="vital-value">${v?.pageSize ? (v.pageSize / 1024 / 1024).toFixed(2) + 'MB' : '-'}</span>
            <span class="vital-desc">転送サイズ</span>
          </div>
          <div class="vital-card">
            <span class="vital-name">DOM要素</span>
            <span class="vital-value">${v?.domElements || '-'}</span>
            <span class="vital-desc">要素数</span>
          </div>
        </div>
      </div>
    `;
  }

  function renderHistoryTab() {
    const prev = state.history.find(h => h.hostname === state.data.hostname && h.timestamp < Date.now() - 60000);
    
    if (!prev) {
      $('#history-content').innerHTML = '<div class="empty-state">まだ過去のスキャンデータがありません。次回アクセス時に比較表示されます。</div>';
      return;
    }

    const currScore = calcScore(state.data).percent;
    const scoreDiff = currScore - prev.score;
    const techDiff = (state.data.detection?.detections?.length || 0) - prev.detectionCount;

    $('#history-content').innerHTML = `
      <div class="card">
        <h3 class="section-title">前回 (${new Date(prev.timestamp).toLocaleDateString('ja-JP')}) との比較</h3>
        <div class="comparison-grid">
          <div class="comp-item">
            <span class="comp-label">セキュリティスコア</span>
            <span class="comp-value" style="color:${scoreDiff>=0?'#a8e6cf':'#ffaaa5'}">${scoreDiff >= 0 ? '↑' : '↓'} ${Math.abs(scoreDiff)}%</span>
          </div>
          <div class="comp-item">
            <span class="comp-label">検出技術数</span>
            <span class="comp-value" style="color:${techDiff>=0?'#a8e6cf':'#ffaaa5'}">${techDiff >= 0 ? '↑' : '↓'} ${Math.abs(techDiff)}個</span>
          </div>
        </div>
      </div>
      <div class="card">
        <h3 class="section-title">スキャン履歴 (${state.history.length}件)</h3>
        <div class="history-list">
          ${state.history.slice(0, 10).map(h => `
            <div class="history-item">
              <span class="history-host">${h(h.hostname)}</span>
              <span class="history-meta">${new Date(h.timestamp).toLocaleDateString('ja-JP')} · スコア${h.score}% · ${h.detectionCount}件</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // === 検索・フィルター ===

  function initSearch() {
    const input = $('#tech-search');
    const clear = $('#clear-search');
    
    input?.addEventListener('input', (e) => {
      state.search = e.target.value.toLowerCase();
      clear.hidden = !state.search;
      if (state.tab === 'tech') renderTechTab();
    });

    clear?.addEventListener('click', () => {
      state.search = '';
      input.value = '';
      clear.hidden = true;
      if (state.tab === 'tech') renderTechTab();
    });

    $$('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.filter = btn.dataset.filter;
        $$('.filter-btn').forEach(b => b.classList.toggle('active', b === btn));
        if (state.tab === 'tech') renderTechTab();
      });
    });
  }

  // === エクスポート ===

  function initExport() {
    const modal = $('#export-modal');
    
    $('#export-btn')?.addEventListener('click', () => modal.hidden = false);
    $('.modal-close')?.addEventListener('click', () => modal.hidden = true);
    modal?.addEventListener('click', (e) => { if (e.target === modal) modal.hidden = true; });
    
    $('#export-json')?.addEventListener('click', () => { exportJSON(); modal.hidden = true; });
    $('#export-csv')?.addEventListener('click', () => { exportCSV(); modal.hidden = true; });
    $('#export-report')?.addEventListener('click', () => { exportReport(); modal.hidden = true; });
    $('#settings-btn')?.addEventListener('click', () => api.runtime.openOptionsPage());
    $('#refresh-btn')?.addEventListener('click', () => location.reload());
  }

  function exportJSON() {
    if (!state.data) return;
    const blob = new Blob([JSON.stringify(state.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tech-detector-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportCSV() {
    if (!state.data?.detection?.detections) return;
    const rows = state.data.detection.detections.map(d => [d.name, LABELS[d.category] || d.category, d.version || '']);
    const csv = [['Name', 'Category', 'Version'], ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tech-detector-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportReport() {
    if (!state.data) return;
    const s = calcScore(state.data);
    const report = `# Tech Detector Enhanced セキュリティレポート

## サイト情報
- **URL**: ${state.data.url}
- **ホスト名**: ${state.data.hostname}
- **検出日時**: ${new Date().toLocaleString('ja-JP')}
- **セキュリティスコア**: ${s.grade} (${s.percent}%)

## 検出技術 (${state.data.detection?.detections?.length || 0}件)
${state.data.detection?.detections?.map(d => `- ${d.name} ${d.version || ''} (${LABELS[d.category] || d.category})`).join('\n') || 'なし'}

## Web Vitals
- **LCP**: ${state.data.vitals?.lcp ? Math.round(state.data.vitals.lcp) + 'ms' : 'N/A'}
- **TTFB**: ${state.data.vitals?.ttfb ? Math.round(state.data.vitals.ttfb) + 'ms' : 'N/A'}

---
Generated by Tech Detector Enhanced
`;
    const blob = new Blob([report], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // === UI ヘルパー ===

  function showLoading(show) {
    $('#loading').hidden = !show;
  }

  function showError(msg) {
    showLoading(false);
    $('#loading').innerHTML = `<p style="color:#ffaaa5;padding:20px">${h(msg)}</p>`;
  }

  // === 開始 ===
  init();
})();
