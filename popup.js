/**
 * Tech Detector Enhanced - Popup UI Controller
 * UI制御・表示ロジックのみ担当
 * @requires utils.js
 * @requires api.js
 */

(() => {
  'use strict';

  // === 状態管理 ===
  const state = {
    data: null,
    tab: 'overview',
    search: '',
    filter: 'all',
    history: []
  };

  // === 初期化 ===
  document.addEventListener('DOMContentLoaded', init);

  /**
   * ポップアップ初期化
   */
  async function init() {
    try {
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

      const hostname = safe(() => new URL(tabUrl).hostname, tabUrl);
      $('#hostname').textContent = hostname;

      // 履歴読み込み
      const histResult = await storageGet('detection_history');
      state.history = histResult.detection_history || [];
      console.log('[Popup] Loaded history:', state.history.length, 'items');

      // データ収集
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
      const filtered = state.history.filter(h => h.hostname !== state.data.hostname);
      const score = calcSecurityScore(state.data).percent;
      filtered.unshift({
        hostname: state.data.hostname,
        url: state.data.url,
        timestamp: Date.now(),
        detectionCount: state.data.detection?.detections?.length || 0,
        score: score
      });
      state.history = filtered.slice(0, 20);
      await storageSet({ detection_history: state.history });
      console.log('[Popup] Saved history:', state.data.hostname, 'score:', score);

      // UI更新
      showLoading(false);
      updateOverview();
      initTabs();
      initSearch();
      initExport();

      $('#last-updated').textContent = new Date().toLocaleTimeString('ja-JP', { 
        hour: '2-digit', 
        minute: '2-digit' 
      });

    } catch (err) {
      console.error('Init error:', err);
      showError('読み込みに失敗しました: ' + err.message);
    }
  }

  // === タブ管理 ===

  /**
   * タブ切り替えを初期化
   */
  function initTabs() {
    $$('.tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.tab = btn.dataset.tab;
        $$('.tab-btn').forEach(b => b.classList.toggle('active', b === btn));
        $$('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + state.tab));

        // タブごとの描画
        const renderers = {
          tech: renderTechTab,
          security: renderSecurityTab,
          performance: renderPerformanceTab,
          details: renderDetailsTab,
          history: renderHistoryTab
        };
        renderers[state.tab]?.();
      });
    });
  }

  // === オーバービュータブ ===

  /**
   * オーバービューを更新
   */
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
    const score = calcSecurityScore(d);
    $('#security-score').textContent = score.grade;
    $('#score-progress').style.width = score.percent + '%';
    $('#score-issues').textContent = score.issues > 0
      ? score.issues + '個の改善が推奨されます'
      : 'セキュリティ設定は良好です';

    // 技術ハイライト
    const highlights = $('#tech-highlights');
    const important = detections
      .filter(x => ['js-framework', 'cms', 'server'].includes(x.category))
      .slice(0, 8);

    if (important.length === 0) {
      highlights.innerHTML = '<span class="empty-text">技術を検出中...</span>';
    } else {
      highlights.innerHTML = important.map(t =>
        `<span class="tech-chip">${ICONS[t.category] || '•'} ${h(t.name)}${
          t.version ? ` <span class="version">v${h(t.version)}</span>` : ''
        }</span>`
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
          <span class="summary-label">TTFB</span>
          <span class="summary-value">${d.vitals.ttfb ? Math.round(d.vitals.ttfb) + 'ms' : '-'}</span>
        </div>
      `;
    }
  }

  // === 技術タブ ===

  /**
   * 技術リストを描画
   */
  function renderTechTab() {
    const list = $('#tech-list');
    const detections = state.data.detection?.detections || [];

    let filtered = detections;
    if (state.filter !== 'all') filtered = filtered.filter(x => x.category === state.filter);
    if (state.search) filtered = filtered.filter(x => x.name.toLowerCase().includes(state.search));

    if (filtered.length === 0) {
      list.innerHTML = `<div class="empty-state"><p>${
        state.search ? '見つかりませんでした' : '検出された技術はありません'
      }</p></div>`;
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

  // === セキュリティタブ ===

  /**
   * セキュリティ情報を描画
   */
  function renderSecurityTab() {
    const d = state.data;

    // ヘッダーチェック
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
      return renderCheckItem(c.label, ok, val);
    }).join('');

    const pct = Math.round((passed / checks.length) * 100);
    const badge = $('#headers-score');
    badge.textContent = pct + '%';
    badge.className = 'badge ' + (pct >= 80 ? 'badge-success' : pct >= 50 ? 'badge-warning' : 'badge-danger');

    // Cookie
    renderCookieSummary(d.cookies);

    // ページ診断
    renderPageSecurity(d.pageSecurity);

    // 脆弱性アラート
    renderVulnerabilities(d.detection?.detections);
  }

  /**
   * チェック項目を描画
   */
  function renderCheckItem(label, ok, value) {
    return `<div class="check-item">
      <span class="check-icon ${ok ? 'pass' : 'fail'}">${ok ? '✓' : '✗'}</span>
      <div class="check-content">
        <div class="check-label">${h(label)}</div>
        ${value ? `<div class="check-value">${h(value.substring(0, 40))}${value.length > 40 ? '...' : ''}</div>` : ''}
      </div>
    </div>`;
  }

  /**
   * Cookieサマリーを描画
   */
  function renderCookieSummary(cookies) {
    if (!cookies || cookies.total === 0) {
      $('#cookie-summary').innerHTML = '<div class="summary-item"><span class="summary-label">Cookieは設定されていません</span></div>';
      return;
    }

    $('#cookie-summary').innerHTML = `
      <div class="summary-item">
        <span class="summary-label">合計</span>
        <span class="summary-value">${cookies.total}個</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">Secure属性なし</span>
        <span class="summary-value" style="color:${cookies.noSecure > 0 ? '#ffaaa5' : '#a8e6cf'}">${cookies.noSecure}個</span>
      </div>
      <div class="summary-item">
        <span class="summary-label">HttpOnly属性なし</span>
        <span class="summary-value" style="color:${cookies.noHttpOnly > 0 ? '#ffaaa5' : '#a8e6cf'}">${cookies.noHttpOnly}個</span>
      </div>
    `;
  }

  /**
   * ページセキュリティを描画
   */
  function renderPageSecurity(pageSec) {
    const issues = [];
    if (pageSec?.mixedContent > 0) issues.push({ label: 'Mixed Content', val: pageSec.mixedContent });
    if (pageSec?.noSri > 0) issues.push({ label: 'SRI未設定', val: pageSec.noSri });
    if (pageSec?.unsafeLinks > 0) issues.push({ label: 'noopener未設定', val: pageSec.unsafeLinks });

    $('#page-security-list').innerHTML = issues.length > 0
      ? issues.map(i => renderCheckItem(i.label + ': ' + i.val + '件', false)).join('')
      : renderCheckItem('重大な問題は検出されませんでした', true);
  }

  /**
   * 脆弱性アラートを描画
   */
  function renderVulnerabilities(detections) {
    const vulnList = $('#vuln-list');
    const alerts = [];

    detections?.forEach(d => {
      const vuln = checkVulnerableVersion(d.name, d.version);
      if (vuln) {
        alerts.push(`
          <div class="check-item">
            <span class="check-icon warn">!</span>
            <div class="check-content">
              <div class="check-label">${h(d.name)} v${h(d.version)}</div>
              <div class="check-value">EOLバージョン。${h(vuln.minVersion)}以降にアップデートしてください</div>
            </div>
          </div>
        `);
      }
    });

    vulnList.innerHTML = alerts.length > 0
      ? alerts.join('')
      : '<div class="check-item"><span class="check-icon pass">✓</span><div class="check-content"><div class="check-label">EOLバージョンは検出されませんでした</div></div></div>';
  }

  // === パフォーマンスタブ ===

  /**
   * パフォーマンス情報を描画
   */
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

  // === 詳細タブ ===

  /**
   * 詳細情報を描画
   */
  function renderDetailsTab() {
    const d = state.data;

    // OGP
    renderOGP(d.ogp);

    // DNS
    renderDNS(d.dnsInfo);

    // Whois
    renderWhois(d.whois);

    // 証明書
    renderCertificate(d.encryption);

    // メール認証
    renderEmailAuth(d.emailAuth);

    // VirusTotal
    renderVirusTotal(d.virusTotal);

    // リンク統計
    renderLinks(d.links);
  }

  function renderOGP(ogp) {
    const el = $('#ogp-preview');
    if (!ogp?.title) {
      el.innerHTML = '<div class="ogp-placeholder"><span>OGP情報なし</span></div>';
      return;
    }

    el.innerHTML = `
      <div style="display:flex;gap:12px;align-items:flex-start">
        ${ogp.image ? `<img src="${h(ogp.image)}" style="width:60px;height:60px;object-fit:cover;border-radius:8px" onerror="this.style.display='none'">` : ''}
        <div style="flex:1;min-width:0">
          <div style="font-weight:600;font-size:13px;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${h(ogp.title)}</div>
          <div style="font-size:11px;color:var(--text-muted);overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${h(ogp.description)}</div>
        </div>
      </div>
    `;
  }

  function renderDNS(dns) {
    $('#dns-details').innerHTML = `
      <div class="detail-item"><span class="detail-label">IPアドレス</span><span class="detail-value">${dns?.ips?.join(', ') || '取得できません'}</span></div>
      <div class="detail-item"><span class="detail-label">ネームサーバー</span><span class="detail-value">${dns?.ns?.join(', ') || '取得できません'}</span></div>
      <div class="detail-item"><span class="detail-label">逆引き（PTR）</span><span class="detail-value">${dns?.ptr || '設定されていません'}</span></div>
    `;
  }

  function renderWhois(whois) {
    if (whois?.ip) {
      $('#whois-details').innerHTML = `
        <div class="detail-item"><span class="detail-label">IPアドレス</span><span class="detail-value">${h(whois.ip)}</span></div>
        <div class="detail-item"><span class="detail-label">国</span><span class="detail-value">${whois.country || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">地域</span><span class="detail-value">${whois.region || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">都市</span><span class="detail-value">${whois.city || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">ISP/組織</span><span class="detail-value">${whois.org || '取得できません'}</span></div>
      `;
    } else {
      $('#whois-details').innerHTML = '<div class="detail-item"><span class="detail-value">ドメイン情報を取得できませんでした</span></div>';
    }
  }

  function renderCertificate(enc) {
    if (enc?.https) {
      $('#cert-details').innerHTML = `
        <div class="detail-item"><span class="detail-label">プロトコル</span><span class="detail-value">HTTPS（暗号化通信）</span></div>
        <div class="detail-item"><span class="detail-label">TLSバージョン</span><span class="detail-value">${enc.tlsVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HTTPバージョン</span><span class="detail-value">${enc.httpVersion || '不明'}</span></div>
        <div class="detail-item"><span class="detail-label">HSTS</span><span class="detail-value">${enc.hsts ? '有効' : '無効'}</span></div>
      `;
    } else {
      $('#cert-details').innerHTML = '<div class="detail-item"><span class="detail-value">HTTP接続のため、証明書情報はありません</span></div>';
    }
  }

  function renderEmailAuth(auth) {
    $('#email-auth-details').innerHTML = ['spf', 'dmarc'].map(k => {
      const ok = !!auth?.[k];
      return `<div class="check-item"><span class="check-icon ${ok ? 'pass' : 'fail'}">${ok ? '✓' : '✗'}</span><div class="check-content"><div class="check-label">${k.toUpperCase()}</div><div class="check-value">${ok ? '設定済み' : '未設定'}</div></div></div>`;
    }).join('');
  }

  function renderVirusTotal(vt) {
    const badge = $('#vt-badge');

    if (vt?.noKey) {
      $('#vt-details').innerHTML = '<div class="detail-item"><span class="detail-value">設定画面でAPIキーを設定してください</span></div>';
      badge.hidden = true;
    } else if (vt?.stats) {
      const s = vt.stats;
      const bad = (s.malicious || 0) + (s.suspicious || 0);
      badge.hidden = false;
      badge.textContent = bad > 0 ? '危険' : '安全';
      badge.className = 'badge ' + (bad > 0 ? 'badge-danger' : 'badge-success');
      $('#vt-details').innerHTML = `<div class="detail-item"><span class="detail-label">検出結果</span><span class="detail-value">悪意:${s.malicious || 0}/疑わしい:${s.suspicious || 0}/安全:${s.harmless || 0}</span></div>`;
    } else {
      badge.hidden = true;
    }
  }

  function renderLinks(links) {
    $('#links-details').innerHTML = `
      <div class="summary-item"><span class="summary-label">総リンク数</span><span class="summary-value">${links?.total || 0}個</span></div>
      <div class="summary-item"><span class="summary-label">外部リンク</span><span class="summary-value">${links?.external || 0}個</span></div>
      <div class="summary-item"><span class="summary-label">内部リンク</span><span class="summary-value">${links?.internal || 0}個</span></div>
    `;
  }

  // === 履歴タブ ===

  /**
   * 履歴比較を描画
   */
  function renderHistoryTab() {
    console.log('[Popup] Rendering history tab. Current hostname:', state.data.hostname);
    console.log('[Popup] History:', state.history);
    
    // 現在のエントリーを除外して過去のエントリーを探す
    const pastEntries = state.history.filter(h => 
      h.hostname === state.data.hostname && h.timestamp < state.data.timestamp
    );
    const prev = pastEntries[0]; // 直近の過去エントリー
    
    console.log('[Popup] Previous entry:', prev);

    if (!prev) {
      $('#history-content').innerHTML = '<div class="empty-state">まだ過去のスキャンデータがありません。<br>（同じサイトを再度アクセスすると比較表示されます）</div>';
      return;
    }

    const currScore = calcSecurityScore(state.data).percent;
    const scoreDiff = currScore - prev.score;
    const techDiff = (state.data.detection?.detections?.length || 0) - prev.detectionCount;

    $('#history-content').innerHTML = `
      <div class="card">
        <h3 class="section-title">前回 (${new Date(prev.timestamp).toLocaleDateString('ja-JP')}) との比較</h3>
        <div class="comparison-grid">
          <div class="comp-item">
            <span class="comp-label">セキュリティスコア</span>
            <span class="comp-value" style="color:${scoreDiff >= 0 ? '#a8e6cf' : '#ffaaa5'}">${scoreDiff >= 0 ? '↑' : '↓'} ${Math.abs(scoreDiff)}%</span>
          </div>
          <div class="comp-item">
            <span class="comp-label">検出技術数</span>
            <span class="comp-value" style="color:${techDiff >= 0 ? '#a8e6cf' : '#ffaaa5'}">${techDiff >= 0 ? '↑' : '↓'} ${Math.abs(techDiff)}個</span>
          </div>
        </div>
      </div>
      <div class="card">
        <h3 class="section-title">スキャン履歴 (${state.history.length}件)</h3>
        <div class="history-list">
          ${state.history.slice(0, 10).map(h => `
            <div class="history-item">
              <span class="history-host">${h(h.hostname)}</span>
              <span class="history-meta">${formatRelativeTime(h.timestamp)} · スコア${h.score}% · ${h.detectionCount}件</span>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  }

  // === 検索・フィルター ===

  /**
   * 検索機能を初期化
   */
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

  /**
   * エクスポート機能を初期化
   */
  function initExport() {
    const modal = $('#export-modal');

    $('#export-btn')?.addEventListener('click', () => modal.hidden = false);
    $('.modal-close')?.addEventListener('click', () => modal.hidden = true);
    modal?.addEventListener('click', (e) => { if (e.target === modal) modal.hidden = true; });

    $('#export-json')?.addEventListener('click', () => { exportJSONData(); modal.hidden = true; });
    $('#export-csv')?.addEventListener('click', () => { exportCSVData(); modal.hidden = true; });
    $('#export-report')?.addEventListener('click', () => { exportReport(); modal.hidden = true; });
    $('#settings-btn')?.addEventListener('click', () => api.runtime.openOptionsPage());
    $('#refresh-btn')?.addEventListener('click', () => location.reload());
  }

  function exportJSONData() {
    if (!state.data) return;
    const filename = `tech-detector-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.json`;
    exportJSON(state.data, filename);
  }

  function exportCSVData() {
    const detections = state.data?.detection?.detections;
    if (!detections) return;

    const rows = [
      ['Name', 'Category', 'Version'],
      ...detections.map(d => [d.name, LABELS[d.category] || d.category, d.version || ''])
    ];
    const filename = `tech-detector-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.csv`;
    exportCSV(rows, filename);
  }

  function exportReport() {
    if (!state.data) return;

    const s = calcSecurityScore(state.data);
    const detections = state.data.detection?.detections || [];

    const report = `# Tech Detector Enhanced セキュリティレポート

## サイト情報
- **URL**: ${state.data.url}
- **ホスト名**: ${state.data.hostname}
- **検出日時**: ${new Date().toLocaleString('ja-JP')}
- **セキュリティスコア**: ${s.grade} (${s.percent}%)

## 検出技術 (${detections.length}件)
${detections.map(d => `- ${d.name} ${d.version || ''} (${LABELS[d.category] || d.category})`).join('\n') || 'なし'}

## Web Vitals
- **LCP**: ${state.data.vitals?.lcp ? Math.round(state.data.vitals.lcp) + 'ms' : 'N/A'}
- **TTFB**: ${state.data.vitals?.ttfb ? Math.round(state.data.vitals.ttfb) + 'ms' : 'N/A'}

---
Generated by Tech Detector Enhanced
`;

    const blob = new Blob([report], { type: 'text/markdown;charset=utf-8;' });
    const filename = `report-${state.data.hostname}-${new Date().toISOString().split('T')[0]}.md`;
    downloadBlob(blob, filename);
  }

  // === UI ヘルパー ===

  function showLoading(show) {
    $('#loading').hidden = !show;
  }

  function showError(msg) {
    showLoading(false);
    $('#loading').innerHTML = `<p style="color:#ffaaa5;padding:20px">${h(msg)}</p>`;
  }
})();
