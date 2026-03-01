/**
 * Tech Detector Enhanced - Options Page
 * 整理版: シンプルで確実なデータフロー
 */
(() => {
  'use strict';
  const api = typeof browser !== 'undefined' ? browser : chrome;

  // === 状態管理 ===
  let historyData = [];

  // === DOM ヘルパー ===
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);
  const h = (s) => s?.replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);

  // === 初期化 ===
  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    console.log('[Options] Initializing...');
    
    try {
      // 設定読み込み
      await loadSettings();
      
      // 履歴読み込み
      await loadHistory();
      
      // イベントリスナー設定
      setupEventListeners();
      
      console.log('[Options] Ready');
    } catch (err) {
      console.error('[Options] Init failed:', err);
      showToast('初期化に失敗しました', 'error');
    }
  }

  // === 設定管理 ===

  async function loadSettings() {
    const { vtApiKey, autoDetect } = await api.storage.sync.get(['vtApiKey', 'autoDetect']);
    
    if (vtApiKey) $('#vt-api-key').value = vtApiKey;
    if (autoDetect !== undefined) $('#auto-detect').checked = autoDetect;
    
    console.log('[Options] Settings loaded');
  }

  async function saveSettings() {
    const vtApiKey = $('#vt-api-key').value.trim();
    const autoDetect = $('#auto-detect').checked;
    
    try {
      await api.storage.sync.set({ vtApiKey, autoDetect });
      showToast('設定を保存しました', 'success');
    } catch (err) {
      console.error('[Options] Save failed:', err);
      showToast('保存に失敗しました', 'error');
    }
  }

  // === 履歴管理 ===

  async function loadHistory() {
    const historyList = $('#history-list');
    const historyStats = $('#history-stats');
    const clearBtn = $('#clear-history');
    
    if (!historyList) {
      console.warn('[Options] history-list element not found');
      return;
    }

    try {
      const result = await api.storage.local.get('detection_history');
      historyData = result.detection_history || [];
      
      console.log('[Options] Loaded history:', historyData.length, 'items', historyData);

      // 統計表示
      if (historyStats) {
        historyStats.innerHTML = `<span class="stat">🌐 ${historyData.length}サイト</span>`;
      }

      // クリアボタン有効化
      if (clearBtn) {
        clearBtn.disabled = historyData.length === 0;
      }

      // 履歴表示
      renderHistory();
      
    } catch (err) {
      console.error('[Options] Load history failed:', err);
      if (historyList) {
        historyList.innerHTML = `
          <div class="error-state">
            <p>読み込みに失敗しました</p>
            <button class="btn" onclick="location.reload()">再読み込み</button>
          </div>
        `;
      }
    }
  }

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
              <span class="meta-time">${formatDate(timestamp)}</span>
              <span class="meta-score ${getScoreClass(score)}">スコア${score}%</span>
              <span class="meta-tech">${detectionCount}件検出</span>
            </div>
          </div>
          <button class="delete-btn" data-index="${index}" title="削除">🗑️</button>
        </div>
      `;
    }).join('');

    // 削除ボタンのイベントリスナー
    historyList.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const idx = parseInt(e.currentTarget.dataset.index, 10);
        deleteHistoryItem(idx);
      });
    });
  }

  async function deleteHistoryItem(index) {
    if (!confirm('この履歴を削除してもよろしいですか？')) return;
    
    try {
      historyData.splice(index, 1);
      await api.storage.local.set({ detection_history: historyData });
      
      renderHistory();
      
      // 統計更新
      const historyStats = $('#history-stats');
      if (historyStats) {
        historyStats.innerHTML = `<span class="stat">🌐 ${historyData.length}サイト</span>`;
      }
      
      // クリアボタン更新
      const clearBtn = $('#clear-history');
      if (clearBtn) {
        clearBtn.disabled = historyData.length === 0;
      }
      
      showToast('削除しました', 'success');
    } catch (err) {
      console.error('[Options] Delete failed:', err);
      showToast('削除に失敗しました', 'error');
    }
  }

  async function clearAllHistory() {
    if (!confirm('すべての履歴を削除してもよろしいですか？\nこの操作は元に戻せません。')) {
      return;
    }

    try {
      await api.storage.local.remove('detection_history');
      historyData = [];
      
      renderHistory();
      
      const historyStats = $('#history-stats');
      if (historyStats) {
        historyStats.innerHTML = `<span class="stat">🌐 0サイト</span>`;
      }
      
      const clearBtn = $('#clear-history');
      if (clearBtn) {
        clearBtn.disabled = true;
      }
      
      showToast('すべての履歴を削除しました', 'success');
    } catch (err) {
      console.error('[Options] Clear failed:', err);
      showToast('削除に失敗しました', 'error');
    }
  }

  // === イベントリスナー ===

  function setupEventListeners() {
    // 設定保存
    $('#save-btn')?.addEventListener('click', saveSettings);
    
    // クリアボタン
    $('#clear-history')?.addEventListener('click', clearAllHistory);
    
    // キャッシュクリア
    $('#clear-cache')?.addEventListener('click', async () => {
      try {
        const { detection_cache } = await api.storage.local.get('detection_cache');
        if (detection_cache) {
          await api.storage.local.remove('detection_cache');
        }
        showToast('キャッシュをクリアしました', 'success');
      } catch (err) {
        console.error('[Options] Cache clear failed:', err);
        showToast('クリアに失敗しました', 'error');
      }
    });
    
    // APIキーテスト
    $('#test-vt')?.addEventListener('click', testVTApi);
    
    console.log('[Options] Event listeners attached');
  }

  async function testVTApi() {
    const key = $('#vt-api-key').value.trim();
    if (!key) {
      showToast('APIキーを入力してください', 'error');
      return;
    }

    const btn = $('#test-vt');
    btn.textContent = 'テスト中...';
    btn.disabled = true;

    try {
      // GoogleのURLでテスト
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
      btn.textContent = '🔍 テスト';
      btn.disabled = false;
    }
  }

  // === ヘルパー ===

  function formatDate(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;
    
    // 1時間以内
    if (diff < 3600000) {
      const mins = Math.floor(diff / 60000);
      return mins < 1 ? 'たった今' : `${mins}分前`;
    }
    // 24時間以内
    if (diff < 86400000) {
      return `${Math.floor(diff / 3600000)}時間前`;
    }
    // 7日以内
    if (diff < 604800000) {
      return `${Math.floor(diff / 86400000)}日前`;
    }
    
    return d.toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' });
  }

  function getScoreClass(score) {
    if (score >= 80) return 'score-good';
    if (score >= 50) return 'score-mid';
    return 'score-bad';
  }

  function showToast(msg, type = 'info') {
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
