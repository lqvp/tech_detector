/**
 * Tech Detector Enhanced - API Module
 * データ収集・外部API通信を担当
 */

// === 検出関連 ===

/**
 * 技術検出を実行
 * @param {number} tabId
 * @param {string} url
 * @returns {Promise<{detections: Array}>}
 */
async function runDetection(tabId, url) {
  return safeAsync(
    () => sendMessage({ type: 'RUN_DETECTION', tabId, url }),
    { detections: [] },
    'Detection'
  );
}

// === 暗号化・接続情報 ===

/**
 * TLS/暗号化情報を取得
 * @param {number} tabId
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getEncryption(tabId, url) {
  if (!url.startsWith('https://')) {
    return { https: false };
  }

  return safeAsync(async () => {
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
      const resp = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
      result.hsts = resp.headers.get('strict-transport-security');
    } catch {}

    return result;
  }, { https: true }, 'Encryption');
}

// === HTTPヘッダー ===

/**
 * セキュリティヘッダーを取得
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getHeaders(url) {
  return safeAsync(async () => {
    const resp = await fetch(url, { 
      method: 'HEAD',
      signal: AbortSignal.timeout(5000)
    });
    
    return {
      csp: resp.headers.get('content-security-policy'),
      xContentTypeOptions: resp.headers.get('x-content-type-options'),
      xFrameOptions: resp.headers.get('x-frame-options'),
      xXssProtection: resp.headers.get('x-xss-protection'),
      referrerPolicy: resp.headers.get('referrer-policy'),
      permissionsPolicy: resp.headers.get('permissions-policy'),
      hsts: resp.headers.get('strict-transport-security')
    };
  }, {}, 'Headers');
}

// === Cookie ===

/**
 * Cookie情報を取得
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getCookies(url) {
  return safeAsync(async () => {
    const cookies = await api.cookies.getAll({ url });
    return {
      total: cookies.length,
      noSecure: cookies.filter(c => !c.secure).length,
      noHttpOnly: cookies.filter(c => !c.httpOnly).length
    };
  }, { total: 0 }, 'Cookies');
}

// === ページセキュリティ ===

/**
 * ページのセキュリティ診断
 * @param {number} tabId
 * @returns {Promise<Object>}
 */
async function getPageSecurity(tabId) {
  return safeAsync(async () => {
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
  }, {}, 'PageSecurity');
}

// === DNS情報 ===

/**
 * DNS情報を取得
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getDnsInfo(url) {
  return safeAsync(async () => {
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
  }, { ips: [], ns: [], ptr: null }, 'DNS');
}

// === メール認証 ===

/**
 * SPF/DMARCを確認
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getEmailAuth(url) {
  return safeAsync(async () => {
    const domain = new URL(url).hostname.replace(/^www\./, '');
    
    const [spfResp, dmarcResp] = await Promise.all([
      fetch(`https://dns.google/resolve?name=${domain}&type=TXT`).then(r => r.json()),
      fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`).then(r => r.json())
    ]);

    const spf = spfResp.Answer?.find(r => r.data?.includes('v=spf1'))?.data;
    const dmarc = dmarcResp.Answer?.find(r => r.data?.toUpperCase().includes('V=DMARC1'))?.data;

    return { spf, dmarc };
  }, {}, 'EmailAuth');
}

// === VirusTotal ===

/**
 * VirusTotalで安全性をチェック
 * @param {string} url
 * @returns {Promise<Object>}
 */
async function getVirusTotal(url) {
  const { vtApiKey } = await syncGet('vtApiKey');
  if (!vtApiKey) return { noKey: true };

  return safeAsync(async () => {
    const id = btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': vtApiKey },
      signal: AbortSignal.timeout(8000)
    });

    if (!resp.ok) return { error: true, status: resp.status };
    
    const json = await resp.json();
    return { stats: json.data.attributes.last_analysis_stats };
  }, null, 'VirusTotal');
}

// === Web Vitals ===

/**
 * パフォーマンス指標を取得
 * @param {number} tabId
 * @returns {Promise<Object>}
 */
async function getWebVitals(tabId) {
  return safeAsync(async () => {
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
  }, {}, 'WebVitals');
}

// === Whois/IP情報 ===

/**
 * IP・Whois情報を取得
 * @param {string} hostname
 * @returns {Promise<Object>}
 */
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
  return safeAsync(async () => {
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
  }, { ip }, 'Whois');
}

// === OGP情報 ===

/**
 * OGP・メタ情報を取得
 * @param {number} tabId
 * @returns {Promise<Object>}
 */
async function getOGP(tabId) {
  return safeAsync(async () => {
    const [{ result }] = await api.scripting.executeScript({
      target: { tabId },
      func: () => {
        const getMeta = (name) => {
          const el = document.querySelector(
            `meta[property="og:${name}"],meta[name="${name}"],meta[name="twitter:${name}"]`
          );
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
  }, {}, 'OGP');
}

// === リンク統計 ===

/**
 * リンク数をカウント
 * @param {number} tabId
 * @returns {Promise<Object>}
 */
async function getLinks(tabId) {
  return safeAsync(async () => {
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
  }, { total: 0, external: 0, internal: 0 }, 'Links');
}

// === 履歴管理 ===

/**
 * 履歴を読み込み
 * @returns {Promise<Array>}
 */
async function loadHistory() {
  const { detection_history } = await storageGet('detection_history');
  return detection_history || [];
}

/**
 * 履歴を保存
 * @param {Object} data
 * @param {Array} currentHistory
 */
async function saveHistory(data, currentHistory = []) {
  const filtered = currentHistory.filter(h => h.hostname !== data.hostname);

  const score = calcSecurityScore(data).percent;

  filtered.unshift({
    hostname: data.hostname,
    url: data.url,
    timestamp: Date.now(),
    detectionCount: data.detection?.detections?.length || 0,
    score: score
  });

  const newHistory = filtered.slice(0, 20);
  await storageSet({ detection_history: newHistory });
  
  console.log('[History] Saved:', data.hostname, 'score:', score);
  return newHistory;
}

/**
 * 履歴から特定項目を削除
 * @param {number} index
 * @param {Array} currentHistory
 */
async function deleteHistoryItem(index, currentHistory) {
  const newHistory = [...currentHistory];
  newHistory.splice(index, 1);
  await storageSet({ detection_history: newHistory });
  return newHistory;
}

/**
 * 履歴を全削除
 */
async function clearAllHistory() {
  await storageRemove('detection_history');
  return [];
}
