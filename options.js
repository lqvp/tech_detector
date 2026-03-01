/**
 * options.js — Tech Detector settings management.
 * Handles: VirusTotal API key, auto-detection toggle, history display, cache management.
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  // DOM Elements
  const keyInput = document.getElementById('apikey');
  const toggleBtn = document.getElementById('toggle-btn');
  const saveApiBtn = document.getElementById('save-api-btn');
  const apiStatusEl = document.getElementById('api-status');
  const autoDetectCheckbox = document.getElementById('auto-detect');
  const autoDetectStatusEl = document.getElementById('auto-detect-status');
  const historyListEl = document.getElementById('history-list');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  const clearCacheBtn = document.getElementById('clear-cache-btn');
  const cacheStatusEl = document.getElementById('cache-status');

  // ─── API Key Management ───

  async function loadApiKey() {
    try {
      const result = await api.storage.sync.get('vtApiKey');
      if (result.vtApiKey) {
        keyInput.value = result.vtApiKey;
      }
    } catch (err) {
      console.error('[Tech Detector] Failed to load API key:', err.message);
    }
  }

  function toggleApiKeyVisibility() {
    const isPassword = keyInput.type === 'password';
    keyInput.type = isPassword ? 'text' : 'password';
    toggleBtn.textContent = isPassword ? '隠す' : '表示';
  }

  async function saveApiKey() {
    const key = keyInput.value.trim();
    try {
      await api.storage.sync.set({ vtApiKey: key });
      apiStatusEl.textContent = key ? 'APIキーを保存しました' : 'APIキーを削除しました';
      apiStatusEl.className = 'status ok';
      setTimeout(() => {
        apiStatusEl.textContent = '';
      }, 3000);
    } catch (err) {
      console.error('[Tech Detector] Failed to save API key:', err.message);
      apiStatusEl.textContent = '保存に失敗しました';
      apiStatusEl.className = 'status err';
    }
  }

  // ─── Auto Detection ───

  async function loadAutoDetectSetting() {
    try {
      const result = await api.storage.sync.get('autoDetect');
      autoDetectCheckbox.checked = result.autoDetect === true;
    } catch (err) {
      console.error('[Tech Detector] Failed to load auto-detect setting:', err.message);
    }
  }

  async function saveAutoDetectSetting() {
    const enabled = autoDetectCheckbox.checked;
    try {
      await api.storage.sync.set({ autoDetect: enabled });
      autoDetectStatusEl.textContent = enabled ? '自動検出を有効にしました' : '自動検出を無効にしました';
      autoDetectStatusEl.className = 'status ok';
      setTimeout(() => {
        autoDetectStatusEl.textContent = '';
      }, 3000);
    } catch (err) {
      console.error('[Tech Detector] Failed to save auto-detect setting:', err.message);
      autoDetectStatusEl.textContent = '設定の保存に失敗しました';
      autoDetectStatusEl.className = 'status err';
    }
  }

  // ─── History Management ───

  function formatDate(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'たった今';
    if (diffMins < 60) return `${diffMins}分前`;
    if (diffHours < 24) return `${diffHours}時間前`;
    if (diffDays < 7) return `${diffDays}日前`;
    return date.toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' });
  }

  async function loadHistory() {
    try {
      const result = await api.storage.local.get('detection_history');
      const history = result.detection_history || [];

      if (history.length === 0) {
        historyListEl.innerHTML = '<div class="empty-history">履歴がありません</div>';
        return;
      }

      historyListEl.innerHTML = '';
      for (const item of history) {
        const div = document.createElement('div');
        div.className = 'history-item';
        div.innerHTML = `
          <div class="history-hostname">${escapeHtml(item.hostname)}</div>
          <div class="history-meta">
            ${item.detectionCount}件検出 · ${formatDate(item.timestamp)}
          </div>
        `;
        historyListEl.appendChild(div);
      }
    } catch (err) {
      console.error('[Tech Detector] Failed to load history:', err.message);
      historyListEl.innerHTML = '<div class="empty-history">読み込みエラー</div>';
    }
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  async function clearHistory() {
    try {
      await api.storage.local.remove('detection_history');
      historyListEl.innerHTML = '<div class="empty-history">履歴を削除しました</div>';
      setTimeout(() => {
        historyListEl.innerHTML = '<div class="empty-history">履歴がありません</div>';
      }, 2000);
    } catch (err) {
      console.error('[Tech Detector] Failed to clear history:', err.message);
      alert('履歴の削除に失敗しました');
    }
  }

  // ─── Cache Management ───

  async function clearExpiredCache() {
    try {
      const response = await api.runtime.sendMessage({ type: 'CLEAR_CACHE' });
      if (response && response.success) {
        cacheStatusEl.textContent = '期限切れのキャッシュを削除しました';
        cacheStatusEl.className = 'status ok';
      } else {
        cacheStatusEl.textContent = 'キャッシュの削除に失敗しました';
        cacheStatusEl.className = 'status err';
      }
      setTimeout(() => {
        cacheStatusEl.textContent = '';
      }, 3000);
    } catch (err) {
      console.error('[Tech Detector] Failed to clear cache:', err.message);
      cacheStatusEl.textContent = 'キャッシュの削除に失敗しました';
      cacheStatusEl.className = 'status err';
    }
  }

  // ─── Event Listeners ───

  toggleBtn.addEventListener('click', toggleApiKeyVisibility);
  saveApiBtn.addEventListener('click', saveApiKey);
  autoDetectCheckbox.addEventListener('change', saveAutoDetectSetting);
  clearHistoryBtn.addEventListener('click', clearHistory);
  clearCacheBtn.addEventListener('click', clearExpiredCache);

  // ─── Initialization ───

  async function init() {
    await Promise.all([
      loadApiKey(),
      loadAutoDetectSetting(),
      loadHistory()
    ]);
  }

  init();
})();
