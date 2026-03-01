/**
 * background.js — Service Worker for Tech Detector_Enhanced.
 * Handles: on-demand detection, header detection, content script injection,
 * badge updates, persistent caching, auto-detection, and history.
 */
(() => {
  'use strict';

  const api = typeof browser !== 'undefined' ? browser : chrome;

  // ─── Constants ───
  const MessageTypes = {
    RUN_DETECTION: 'RUN_DETECTION',
    DETECTION_RESULT: 'DETECTION_RESULT',
    GET_DETECTIONS: 'GET_DETECTIONS',
    CLEAR_CACHE: 'CLEAR_CACHE'
  };

  const CACHE_KEY_PREFIX = 'detection_cache_';
  const HISTORY_KEY = 'detection_history';
  const MAX_HISTORY = 50;
  const CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

  // In-memory detection store: tabId -> { url, detections[], timestamp }
  const tabDetections = {};

  // Pending detection promises: tabId -> { resolve, timer }
  const pendingDetections = new Map();

  // ─── Technology Loading ───

  let technologies = null;
  async function loadTechnologies() {
    try {
      const url = api.runtime.getURL('technologies.json');
      const resp = await fetch(url);
      technologies = await resp.json();
    } catch (e) {
      console.error('[Tech Detector_Enhanced] Failed to load technologies.json:', e.message);
    }
  }

  // ─── Cache Management ───

  async function saveToStorage(tabId, data) {
    try {
      const key = `${CACHE_KEY_PREFIX}${tabId}`;
      await api.storage.local.set({
        [key]: { ...data, timestamp: Date.now() }
      });
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Failed to save to storage:', e.message);
    }
  }

  async function loadFromStorage(tabId) {
    try {
      const key = `${CACHE_KEY_PREFIX}${tabId}`;
      const result = await api.storage.local.get(key);
      const cached = result[key];
      
      if (cached && (Date.now() - cached.timestamp) < CACHE_EXPIRY) {
        return cached;
      }
      return null;
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Failed to load from storage:', e.message);
      return null;
    }
  }

  async function clearExpiredCache() {
    try {
      const allData = await api.storage.local.get();
      const keysToRemove = [];
      
      for (const [key, value] of Object.entries(allData)) {
        if (key.startsWith(CACHE_KEY_PREFIX)) {
          if (!value.timestamp || (Date.now() - value.timestamp) >= CACHE_EXPIRY) {
            keysToRemove.push(key);
          }
        }
      }
      
      if (keysToRemove.length > 0) {
        await api.storage.local.remove(keysToRemove);
        console.log(`[Tech Detector_Enhanced] Cleared ${keysToRemove.length} expired cache entries`);
      }
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Failed to clear expired cache:', e.message);
    }
  }

  // ─── History Management ───

  async function addToHistory(data) {
    try {
      const result = await api.storage.local.get(HISTORY_KEY);
      const history = result[HISTORY_KEY] || [];
      
      const url = data.url;
      let hostname;
      try {
        hostname = data.hostname || new URL(url).hostname;
      } catch {
        hostname = url;
      }
      
      // 同じホスト名のエントリを削除（常に最新のみ保持）
      const filtered = history.filter(h => h.hostname !== hostname);
      
      // スコアは最低限の計算（詳細はポップアップ側で計算）
      filtered.unshift({
        hostname,
        url,
        timestamp: Date.now(),
        detectionCount: data.detections?.length || 0,
        score: data.score || 0
      });
      
      await api.storage.local.set({
        [HISTORY_KEY]: filtered.slice(0, MAX_HISTORY)
      });
      
      console.log('[Background] History saved:', hostname, filtered.length, 'items');
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Failed to add to history:', e.message);
    }
  }

  // ─── Detection Functions ───

  function detectFromHeaders(techs, headers) {
    const results = [];
    for (const tech of techs) {
      if (!tech.headers) continue;
      for (const [headerName, pattern] of Object.entries(tech.headers)) {
        const value = headers[headerName.toLowerCase()];
        if (value === undefined) continue;
        if (!pattern) {
          results.push({
            name: tech.name,
            category: tech.category,
            version: null,
            methods: ['headers']
          });
          break;
        }
        try {
          const re = new RegExp(pattern, 'i');
          const match = re.exec(value);
          if (match) {
            results.push({
              name: tech.name,
              category: tech.category,
              version: match[1] || null,
              methods: ['headers']
            });
            break;
          }
        } catch (e) {
          console.warn('[Tech Detector_Enhanced] Invalid regex pattern:', pattern, e.message);
        }
      }
    }
    return results;
  }

  function mergeDetections(existing, incoming) {
    const map = new Map();
    for (const d of existing) {
      map.set(d.name, { ...d, methods: [...(d.methods || [])] });
    }
    for (const d of incoming) {
      const e = map.get(d.name);
      if (e) {
        if (!e.version && d.version) e.version = d.version;
        for (const m of (d.methods || [])) {
          if (!e.methods.includes(m)) e.methods.push(m);
        }
      } else {
        map.set(d.name, {
          name: d.name,
          category: d.category,
          version: d.version || null,
          methods: [...(d.methods || [])]
        });
      }
    }
    return Array.from(map.values());
  }

  function updateBadge(tabId) {
    const data = tabDetections[tabId];
    const count = data ? data.detections.length : 0;
    const text = count > 0 ? String(count) : '';
    api.action.setBadgeText({ text, tabId });
    api.action.setBadgeBackgroundColor({ color: '#4A90D9', tabId });
  }

  async function runDetection(tabId, tabUrl, skipCache = false) {
    // Cancel any pending detection for this tab
    if (pendingDetections.has(tabId)) {
      clearTimeout(pendingDetections.get(tabId).timer);
      pendingDetections.delete(tabId);
    }

    // Check cache first (unless skipped)
    if (!skipCache) {
      const cached = await loadFromStorage(tabId);
      if (cached && cached.url === tabUrl) {
        tabDetections[tabId] = cached;
        updateBadge(tabId);
        return cached;
      }
    }

    // Reset detections
    tabDetections[tabId] = { url: tabUrl, detections: [], timestamp: Date.now() };

    if (!technologies) await loadTechnologies();
    if (!technologies) return tabDetections[tabId];

    // 1. Header detection via fetch
    try {
      const resp = await fetch(tabUrl, { method: 'HEAD' });
      const headers = {};
      resp.headers.forEach((value, name) => {
        headers[name.toLowerCase()] = value;
      });
      const headerResults = detectFromHeaders(technologies.technologies, headers);
      if (headerResults.length > 0) {
        tabDetections[tabId].detections = mergeDetections(
          tabDetections[tabId].detections,
          headerResults
        );
      }
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Header fetch failed:', e.message);
    }

    // 2. Inject content scripts programmatically
    try {
      await api.scripting.executeScript({
        target: { tabId },
        files: ['browser-polyfill.js', 'detect.js', 'content.js']
      });
      await api.scripting.executeScript({
        target: { tabId },
        files: ['content-main.js'],
        world: 'MAIN'
      });
    } catch (e) {
      console.warn('[Tech Detector_Enhanced] Content script injection failed:', e.message);
      updateBadge(tabId);
      return tabDetections[tabId];
    }

    // 3. Wait for content script results (with timeout)
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingDetections.delete(tabId);
        updateBadge(tabId);
        // Save to storage and history
        saveToStorage(tabId, tabDetections[tabId]);
        addToHistory(tabDetections[tabId]);
        resolve(tabDetections[tabId]);
      }, 3000);

      pendingDetections.set(tabId, { resolve, timer });
    });
  }

  // ─── Auto Detection ───

  async function shouldAutoDetect() {
    try {
      const result = await api.storage.sync.get('autoDetect');
      return result.autoDetect === true;
    } catch (e) {
      return false;
    }
  }

  async function handleTabUpdate(tabId, changeInfo, tab) {
    if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
      const autoDetect = await shouldAutoDetect();
      if (autoDetect) {
        // Small delay to let page stabilize
        setTimeout(() => {
          runDetection(tabId, tab.url).catch(e => 
            console.warn('[Tech Detector_Enhanced] Auto-detection failed:', e.message)
          );
        }, 1000);
      }
    }
  }

  // ─── Message Handling ───

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Content script detection results
    if (message.type === MessageTypes.DETECTION_RESULT && sender.tab) {
      const tabId = sender.tab.id;
      if (!tabDetections[tabId]) {
        tabDetections[tabId] = {
          url: message.url || sender.tab.url,
          detections: [],
          timestamp: Date.now()
        };
      }
      tabDetections[tabId].detections = mergeDetections(
        tabDetections[tabId].detections,
        message.detections || []
      );

      if (pendingDetections.has(tabId)) {
        const pending = pendingDetections.get(tabId);
        clearTimeout(pending.timer);
        updateBadge(tabId);
        // Save to storage and history
        saveToStorage(tabId, tabDetections[tabId]);
        addToHistory(tabDetections[tabId]);
        pending.resolve(tabDetections[tabId]);
        pendingDetections.delete(tabId);
      }

      return false;
    }

    // Run detection (triggered by popup click)
    if (message.type === MessageTypes.RUN_DETECTION) {
      runDetection(message.tabId, message.url, message.skipCache)
        .then((result) => sendResponse(result))
        .catch((e) => {
          console.error('[Tech Detector_Enhanced] Detection failed:', e.message);
          sendResponse({ url: message.url || '', detections: [] });
        });
      return true; // async sendResponse
    }

    // Get cached detections
    if (message.type === MessageTypes.GET_DETECTIONS) {
      const data = tabDetections[message.tabId];
      if (data) {
        sendResponse(data);
      } else {
        // Try loading from storage
        loadFromStorage(message.tabId).then(cached => {
          sendResponse(cached || { url: '', detections: [] });
        });
        return true;
      }
      return false;
    }

    // Clear cache
    if (message.type === MessageTypes.CLEAR_CACHE) {
      clearExpiredCache().then(() => {
        sendResponse({ success: true });
      });
      return true;
    }

    return false;
  });

  // ─── Event Listeners ───

  // Open popup window centered on screen
  api.action.onClicked.addListener(async (tab) => {
    const width = 420;
    const height = 580;
    const currentWindow = await api.windows.getCurrent();
    const left = Math.round(currentWindow.left + (currentWindow.width - width) / 2);
    const top = Math.round(currentWindow.top + (currentWindow.height - height) / 2);
    const params = new URLSearchParams({ tabId: tab.id, tabUrl: tab.url });
    api.windows.create({
      url: `${api.runtime.getURL('popup.html')}?${params}`,
      type: 'popup',
      width,
      height,
      left,
      top
    });
  });

  // Auto-detection on tab update
  api.tabs.onUpdated.addListener(handleTabUpdate);

  // Clean up when tabs are closed
  api.tabs.onRemoved.addListener((tabId) => {
    delete tabDetections[tabId];
    if (pendingDetections.has(tabId)) {
      clearTimeout(pendingDetections.get(tabId).timer);
      pendingDetections.delete(tabId);
    }
    // Clean up storage
    api.storage.local.remove(`${CACHE_KEY_PREFIX}${tabId}`);
  });

  // Periodic cache cleanup
  api.alarms?.create('cacheCleanup', { periodInMinutes: 60 });
  api.alarms?.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cacheCleanup') {
      clearExpiredCache();
    }
  });

  // Manual cleanup on startup
  clearExpiredCache();

  // Initialize
  loadTechnologies();
})();
