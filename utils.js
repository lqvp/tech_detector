/**
 * Tech Detector Enhanced - Utilities
 * 共通関数・定数・ヘルパーを提供
 */

// === ブラウザAPIポリフィル ===
const api = typeof browser !== 'undefined' ? browser : chrome;

// === アイコン定数 ===
const ICONS = {
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

// === カテゴリラベル ===
const LABELS = {
  'js-framework': 'フレームワーク',
  'js-library': 'ライブラリ',
  'css-framework': 'CSS',
  'cms': 'CMS',
  'server': 'サーバー',
  'analytics': 'アナリティクス',
  'cdn': 'CDN',
  'font': 'フォント',
  'hosting': 'ホスティング',
  'build': 'ビルド',
  'security': 'セキュリティ',
  'os': 'OS'
};

// === 脆弱性情報（EOLバージョン） ===
const EOL_VERSIONS = {
  'jQuery': { min: '3.0.0', url: 'https://jquery.com/upgrade-guide/' },
  'React': { min: '18.0.0', url: 'https://react.dev/' },
  'Angular': { min: '15.0.0', url: 'https://angular.io/guide/update-to-latest-version' },
  'Vue.js': { min: '3.0.0', url: 'https://v3.vuejs.org/' },
  'Bootstrap': { min: '5.0.0', url: 'https://getbootstrap.com/docs/5.0/migration/' },
  'PHP': { min: '8.0.0', url: 'https://www.php.net/supported-versions.php' },
  'WordPress': { min: '6.0.0', url: 'https://wordpress.org/download/' }
};

// === エラーハンドリングラッパー ===

/**
 * 非同期関数を安全に実行
 * @template T
 * @param {() => Promise<T>} fn - 実行する関数
 * @param {T} [fallback=null] - エラー時のデフォルト値
 * @param {string} [context=''] - エラーログのコンテキスト
 * @returns {Promise<T>}
 */
async function safeAsync(fn, fallback = null, context = '') {
  try {
    return await fn();
  } catch (err) {
    if (context) {
      console.warn(`[${context}] Failed:`, err.message);
    }
    return fallback;
  }
}

/**
 * 同期関数を安全に実行
 * @template T
 * @param {() => T} fn - 実行する関数
 * @param {T} [fallback=null] - エラー時のデフォルト値
 * @param {string} [context=''] - エラーログのコンテキスト
 * @returns {T}
 */
function safe(fn, fallback = null, context = '') {
  try {
    return fn();
  } catch (err) {
    if (context) {
      console.warn(`[${context}] Failed:`, err.message);
    }
    return fallback;
  }
}

// === DOMヘルパー ===

/**
 * querySelectorのショートカット
 * @param {string} selector
 * @param {ParentNode} [parent=document]
 * @returns {Element|null}
 */
function $(selector, parent = document) {
  return parent.querySelector(selector);
}

/**
 * querySelectorAllのショートカット
 * @param {string} selector
 * @param {ParentNode} [parent=document]
 * @returns {NodeListOf<Element>}
 */
function $$(selector, parent = document) {
  return parent.querySelectorAll(selector);
}

/**
 * XSS対策のエスケープ
 * @param {string} str
 * @returns {string}
 */
function h(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);
}

/**
 * 要素の中身を安全にクリア
 * @param {Element} el
 */
function clearElement(el) {
  if (el) el.textContent = '';
}

// === 日時ヘルパー ===

/**
 * タイムスタンプを相対時間で表示
 * @param {number} timestamp
 * @returns {string}
 */
function formatRelativeTime(timestamp) {
  if (!timestamp) return '-';
  
  const now = Date.now();
  const diff = now - timestamp;
  
  if (diff < 60000) return 'たった今';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分前`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}時間前`;
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}日前`;
  
  return new Date(timestamp).toLocaleDateString('ja-JP', { month: 'short', day: 'numeric' });
}

/**
 * 日時を短い形式で表示
 * @param {number} timestamp
 * @returns {string}
 */
function formatDateTime(timestamp) {
  if (!timestamp) return '-';
  return new Date(timestamp).toLocaleString('ja-JP', { 
    month: 'short', 
    day: 'numeric', 
    hour: '2-digit', 
    minute: '2-digit' 
  });
}

// === スコア計算 ===

/**
 * セキュリティスコアを計算
 * @param {Object} data
 * @returns {{grade: string, percent: number, issues: number}}
 */
function calcSecurityScore(data) {
  let score = 100;
  let issues = 0;

  if (!data.encryption?.https) { score -= 30; issues++; }
  if (!data.headers?.csp) { score -= 5; issues++; }
  if (!data.headers?.xContentTypeOptions) { score -= 5; issues++; }
  if (!data.headers?.xFrameOptions) { score -= 5; issues++; }
  if (!data.headers?.hsts && !data.encryption?.hsts) { score -= 10; issues++; }
  if (data.cookies?.noSecure > 0) { score -= 5; issues++; }
  if (data.cookies?.noHttpOnly > 0) { score -= 5; issues++; }
  if (data.pageSecurity?.mixedContent > 0) { score -= 15; issues++; }
  if (data.virusTotal?.stats?.malicious > 0) { score -= 30; issues++; }

  const percent = Math.max(0, score);
  let grade = 'A';
  if (percent < 90) grade = 'B';
  if (percent < 70) grade = 'C';
  if (percent < 50) grade = 'D';
  if (percent < 30) grade = 'F';

  return { grade, percent, issues };
}

/**
 * スコアに応じたCSSクラスを取得
 * @param {number} score
 * @returns {string}
 */
function getScoreClass(score) {
  if (score >= 80) return 'score-good';
  if (score >= 50) return 'score-mid';
  return 'score-bad';
}

// === エクスポートヘルパー ===

/**
 * Blobをダウンロード
 * @param {Blob} blob
 * @param {string} filename
 */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * JSONをエクスポート
 * @param {Object} data
 * @param {string} filename
 */
function exportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  downloadBlob(blob, filename);
}

/**
 * CSVをエクスポート
 * @param {string[][]} rows
 * @param {string} filename
 */
function exportCSV(rows, filename) {
  const csv = rows.map(r => 
    r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')
  ).join('\n');
  const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, filename);
}

// === ストレージヘルパー ===

/**
 * ローカルストレージから取得
 * @param {string|string[]} keys
 * @returns {Promise<Object>}
 */
function storageGet(keys) {
  return api.storage.local.get(keys);
}

/**
 * ローカルストレージに保存
 * @param {Object} data
 * @returns {Promise<void>}
 */
function storageSet(data) {
  return api.storage.local.set(data);
}

/**
 * ローカルストレージから削除
 * @param {string|string[]} keys
 * @returns {Promise<void>}
 */
function storageRemove(keys) {
  return api.storage.local.remove(keys);
}

/**
 * 同期ストレージから取得
 * @param {string|string[]} keys
 * @returns {Promise<Object>}
 */
function syncGet(keys) {
  return api.storage.sync.get(keys);
}

/**
 * 同期ストレージに保存
 * @param {Object} data
 * @returns {Promise<void>}
 */
function syncSet(data) {
  return api.storage.sync.set(data);
}

// === バックグラウンド通信 ===

/**
 * バックグラウンドへメッセージ送信
 * @param {Object} message
 * @returns {Promise<any>}
 */
function sendMessage(message) {
  return api.runtime.sendMessage(message);
}

// === バージョンヘルパー ===

/**
 * セマンティックバージョンを比較
 * @param {string} v1
 * @param {string} v2
 * @returns {number} -1: v1<v2, 0: equal, 1: v1>v2
 */
function compareVersion(v1, v2) {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const a = parts1[i] || 0;
    const b = parts2[i] || 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

/**
 * バージョンがEOLかチェック
 * @param {string} name - 技術名
 * @param {string} version - 現在のバージョン
 * @returns {{isVulnerable: boolean, minVersion: string, url: string}|null}
 */
function checkVulnerableVersion(name, version) {
  const eol = EOL_VERSIONS[name];
  if (!eol || !version) return null;
  
  if (compareVersion(version, eol.min) < 0) {
    return { isVulnerable: true, minVersion: eol.min, url: eol.url };
  }
  return null;
}
