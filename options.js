/**
 * Tech Detector Enhanced - Options Page
 * 設定画面のUI制御
 * @requires utils.js
 */

(() => {
  'use strict';

  // === 状態管理 ===
  let historyData = [];

  // === 初期化 ===
  document.addEventListener('DOMContentLoaded', init);

  /**
   * 設定画面初期化
   */
  async function init() {
    console.log('[Options] Initializing...');

    try {
      await loadSettings();
      await loadHistory();
      setupEventListeners();

      console.log('[Options] Ready');
    } catch (err) {
      console.error('[Options] Init failed:', err);
      showToast('初期化に失敗しました', 'error');
    }
  }

  // === 設定管理 ===

  /**
   * 設定を読み込み
   */
  async function loadSettings() {
    const { vtApiKey, autoDetect } = await syncGet(['vtApiKey', 'autoDetect']);

    const keyInput = $('#vt-api-key');
    const autoCheck = $('#auto-detect');

    if (keyInput && vtApiKey) keyInput.value = vtApiKey;
    if (autoCheck && autoDetect !== undefined) autoCheck.checked = autoDetect;

    console.log('[Options] Settings loaded');
  }

  /**
   * 設定を保存
   */
  async function saveSettings() {
    const keyInput = $('#vt-api-key');
    const autoCheck = $('#auto-detect');

    const vtApiKey = keyInput?.value?.trim() || '';
    const autoDetect = autoCheck?.checked ?? false;

    try {
      await syncSet({ vtApiKey, autoDetect });
      showToast('設定を保存しました', 'success');
    } catch (err) {
      console.error('[Options] Save failed:', err);
      showToast('保存に失敗しました', 'error');
    }
  }

  // === 履歴管理 ===

  /**
   * 履歴を読み込み
   */
  async function loadHistory() {
    const historyList = $('#history-list');
    const historyStats = $('#history-stats');
    const clearBtn = $('#clear-history');

    try {
      const result = await storageGet('detection_history');
      historyData = result.detection_history || [];
      console.log('[Options] Loaded history:', historyData.length, 'items');

      // 統計表示
      if (historyStats) {
        historyStats.innerHTML = `<span class="stat">🌐 ${historyData.length}サイト</span>`;
      }

      // クリアボタン有効化
      if (clearBtn) {
        clearBtn.disabled = historyData.length === 0;
      }

      renderHistory();

    } catch (err) {
      console.error('[Options] Load history failed:', err);
      if (historyList) {
        historyList.innerHTML = `
          <div class="error-state">
            <p>読み込みに失敗しました</p>
            <button class="btn" id="reload-btn">再読み込み</button>
          </div>
        `;
        $('#reload-btn')?.addEventListener('click', () => location.reload());
      }
    }
  }

  /**
   * 履歴リストを描画
   */
  function renderHistory() {
    const historyList = $('#history-list');
    if (!historyList) return;

    // データが配列でない場合は空配列に
    if (!Array.isArray(historyData)) {
      console.warn('[Options] historyData is not array:', historyData);
      historyData = [];
    }

    if (historyData.length === 0) {
      historyList.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">📊</div>
          <p>まだ履歴がありません</p>
          <p class="empty-desc">ポップアップからサイトを検出すると、ここに表示されます</p>
        </div>
      `;
      return;
    }

    historyList.innerHTML = historyData.map((item, index) => {
      const hostname = item.hostname || 'unknown';
      const score = typeof item.score === 'number' ? item.score : 0;
      const detectionCount = typeof item.detectionCount === 'number' ? item.detectionCount : 0;
      const timestamp = item.timestamp || Date.now();

      return `
        <div class="history-item" data-index="${index}">
          <div class="history-main">
            <div class="history-host">
              <span class="host-icon">🌐</span>
              <span class="host-name">${h(hostname)}</span>
            </div>
            <div class="history-meta">
              <span class="meta-time">${formatRelativeTime(timestamp)}</span>
              <span class="meta-score ${getScoreClass(score)}">スコア${score}%</span>
              <span class="meta-tech">${detectionCount}件検出</span>
            </div>
          </div>
          <button class="delete-btn" data-index="${index}" data-action="delete" title="削除">🗑️</button>
        </div>
      `;
    }).join('');
    
    console.log('[Options] Rendered', historyData.length, 'history items');
  }

  /**
   * 履歴項目削除ハンドラ
   * @param {number} index
   */
  async function handleDeleteItem(index) {
    console.log('[Options] Delete requested for index:', index);
    if (!confirm('この履歴を削除してもよろしいですか？')) return;

    try {
      const newHistory = [...historyData];
      newHistory.splice(index, 1);
      await storageSet({ detection_history: newHistory });
      historyData = newHistory;
      renderHistory();
      updateHistoryStats();
      showToast('削除しました', 'success');
    } catch (err) {
      console.error('[Options] Delete failed:', err);
      showToast('削除に失敗しました: ' + err.message, 'error');
    }
  }

  /**
   * 履歴全削除ハンドラ
   */
  async function handleClearAll() {
    console.log('[Options] Clear all requested');
    if (!confirm('すべての履歴を削除してもよろしいですか？\nこの操作は元に戻せません。')) {
      return;
    }

    try {
      console.log('[Options] Calling clearAllHistory...');
      await storageRemove('detection_history');
      historyData = [];
      renderHistory();
      updateHistoryStats();
      showToast('すべての履歴を削除しました', 'success');
    } catch (err) {
      console.error('[Options] Clear failed:', err);
      showToast('削除に失敗しました: ' + err.message, 'error');
    }
  }

  /**
   * 履歴統計表示を更新
   */
  function updateHistoryStats() {
    const historyStats = $('#history-stats');
    const clearBtn = $('#clear-history');

    if (historyStats) {
      historyStats.innerHTML = `<span class="stat">🌐 ${historyData.length}サイト</span>`;
    }
    if (clearBtn) {
      clearBtn.disabled = historyData.length === 0;
    }
  }

  // === イベントリスナー ===

  /**
   * イベントリスナーを設定
   */
  function setupEventListeners() {
    // 設定保存
    $('#save-btn')?.addEventListener('click', saveSettings);

    // 履歴全削除
    const clearBtn = $('#clear-history');
    if (clearBtn) {
      console.log('[Options] Attaching clear-all listener');
      clearBtn.addEventListener('click', handleClearAll);
    } else {
      console.warn('[Options] Clear button not found');
    }

    // キャッシュクリア
    $('#clear-cache')?.addEventListener('click', handleClearCache);

    // APIキーテスト
    $('#test-vt')?.addEventListener('click', testVTApi);
    
    // 履歴リストのイベント委譲（削除ボタン）
    const historyList = $('#history-list');
    if (historyList) {
      historyList.addEventListener('click', (e) => {
        const btn = e.target.closest('.delete-btn');
        if (btn) {
          e.stopPropagation();
          const idx = parseInt(btn.dataset.index, 10);
          console.log('[Options] Delete button clicked for index:', idx);
          handleDeleteItem(idx);
        }
      });
    }

    console.log('[Options] Event listeners attached');
  }

  /**
   * キャッシュクリアハンドラ
   */
  async function handleClearCache() {
    try {
      await storageRemove('detection_cache');
      showToast('キャッシュをクリアしました', 'success');
    } catch (err) {
      console.error('[Options] Cache clear failed:', err);
      showToast('クリアに失敗しました', 'error');
    }
  }

  /**
   * VirusTotal APIテスト
   */
  async function testVTApi() {
    const keyInput = $('#vt-api-key');
    const key = keyInput?.value?.trim();

    if (!key) {
      showToast('APIキーを入力してください', 'error');
      return;
    }

    const btn = $('#test-vt');
    const originalText = btn?.textContent;

    if (btn) {
      btn.textContent = 'テスト中...';
      btn.disabled = true;
    }

    try {
      const url = 'https://www.google.com';
      const id = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

      const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { 'x-apikey': key },
        signal: AbortSignal.timeout(10000)
      });

      if (resp.ok) {
        showToast('APIキーは有効です', 'success');
      } else if (resp.status === 401) {
        showToast('APIキーが無効です', 'error');
      } else {
        showToast(`エラー: HTTP ${resp.status}`, 'error');
      }
    } catch (err) {
      console.error('[Options] VT test failed:', err);
      showToast('テストに失敗しました: ' + err.message, 'error');
    } finally {
      if (btn) {
        btn.textContent = originalText;
        btn.disabled = false;
      }
    }
  }

  // === Toast通知 ===

  /**
   * Toast通知を表示
   * @param {string} msg
   * @param {'info'|'success'|'error'} type
   */
  function showToast(msg, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    document.body.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('show'));

    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }

  console.log('[Options] Script loaded');
})();
