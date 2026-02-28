/**
 * options.js — VirusTotal API key management.
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  const keyInput = document.getElementById('apikey');
  const toggleBtn = document.getElementById('toggle-btn');
  const saveBtn = document.getElementById('save-btn');
  const statusEl = document.getElementById('status');

  // Load saved key
  api.storage.sync.get('vtApiKey').then(result => {
    if (result.vtApiKey) keyInput.value = result.vtApiKey;
  });

  // Toggle visibility
  toggleBtn.addEventListener('click', () => {
    const isPassword = keyInput.type === 'password';
    keyInput.type = isPassword ? 'text' : 'password';
    toggleBtn.textContent = isPassword ? '隠す' : '表示';
  });

  // Save
  saveBtn.addEventListener('click', () => {
    const key = keyInput.value.trim();
    api.storage.sync.set({ vtApiKey: key }).then(() => {
      statusEl.textContent = key ? '保存しました' : 'APIキーを削除しました';
      statusEl.className = 'status ok';
    }).catch(() => {
      statusEl.textContent = '保存に失敗しました';
      statusEl.className = 'status err';
    });
  });
})();
