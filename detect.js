/**
 * detect.js — Pure detection engine for Tech Detector_Enhanced
 * Provides functions to match technologies against page signals.
 */
var TechDetector = (() => {
  'use strict';

  /**
   * Test a regex pattern string against a value.
   * Returns the match array or null.
   */
  function testPattern(pattern, value) {
    if (!pattern || !value) return null;
    try {
      const re = new RegExp(pattern, 'i');
      return re.exec(value);
    } catch (err) {
      console.warn('[Tech Detector_Enhanced] Invalid regex pattern:', pattern, err.message);
      return null;
    }
  }

  /**
   * Detect technologies from <script src> URLs.
   * @param {Array} techs - technology definitions
   * @param {string[]} scriptSrcs - list of script src attribute values
   * @returns {Object[]} matched technologies
   */
  function detectScripts(techs, scriptSrcs) {
    const results = [];
    for (const tech of techs) {
      if (!tech.scripts) continue;
      for (const src of scriptSrcs) {
        if (testPattern(tech.scripts, src)) {
          results.push({ name: tech.name, category: tech.category, method: 'scripts' });
          break;
        }
      }
    }
    return results;
  }

  /**
   * Detect technologies from DOM selectors.
   * @param {Array} techs - technology definitions
   * @param {Function} querySelectorFn - (selector) => boolean (element exists)
   * @returns {Object[]} matched technologies
   */
  function detectDom(techs, querySelectorFn) {
    const results = [];
    for (const tech of techs) {
      if (!tech.dom) continue;
      const selectors = tech.dom.split(',').map(s => s.trim());
      for (const sel of selectors) {
        try {
          if (querySelectorFn(sel)) {
            results.push({ name: tech.name, category: tech.category, method: 'dom' });
            break;
          }
        } catch (err) {
          console.warn('[Tech Detector_Enhanced] Invalid selector:', sel, err.message);
        }
      }
    }
    return results;
  }

  /**
   * Detect technologies from <meta> tags.
   * @param {Array} techs - technology definitions
   * @param {Object} metaTags - { name: content, ... }
   * @returns {Object[]} matched technologies with optional version
   */
  function detectMeta(techs, metaTags) {
    const results = [];
    for (const tech of techs) {
      if (!tech.meta) continue;
      for (const [metaName, pattern] of Object.entries(tech.meta)) {
        const content = metaTags[metaName.toLowerCase()];
        if (content === undefined) continue;
        if (!pattern) {
          results.push({ name: tech.name, category: tech.category, method: 'meta' });
          break;
        }
        const match = testPattern(pattern, content);
        if (match) {
          const entry = { name: tech.name, category: tech.category, method: 'meta' };
          if (match[1]) entry.version = match[1];
          results.push(entry);
          break;
        }
      }
    }
    return results;
  }

  /**
   * Detect technologies from HTML source (first 50KB).
   * @param {Array} techs - technology definitions
   * @param {string} html - HTML source string
   * @returns {Object[]} matched technologies
   */
  function detectHtml(techs, html) {
    const results = [];
    if (!html) return results;
    const snippet = html.substring(0, 50000);
    for (const tech of techs) {
      if (!tech.html) continue;
      if (testPattern(tech.html, snippet)) {
        results.push({ name: tech.name, category: tech.category, method: 'html' });
      }
    }
    return results;
  }

  /**
   * Detect technologies from HTTP response headers.
   * @param {Array} techs - technology definitions
   * @param {Object} headers - { headerName: value, ... } (lowercase keys)
   * @returns {Object[]} matched technologies with optional version
   */
  function detectHeaders(techs, headers) {
    const results = [];
    if (!headers) return results;
    for (const tech of techs) {
      if (!tech.headers) continue;
      for (const [headerName, pattern] of Object.entries(tech.headers)) {
        const value = headers[headerName.toLowerCase()];
        if (value === undefined) continue;
        if (!pattern) {
          results.push({ name: tech.name, category: tech.category, method: 'headers' });
          break;
        }
        const match = testPattern(pattern, value);
        if (match) {
          const entry = { name: tech.name, category: tech.category, method: 'headers' };
          if (match[1]) entry.version = match[1];
          results.push(entry);
          break;
        }
      }
    }
    return results;
  }

  /**
   * Detect technologies from JS global variables.
   * @param {Array} techs - technology definitions
   * @param {Object} globals - { varName: { exists, version }, ... }
   * @returns {Object[]} matched technologies with optional version
   */
  function detectJs(techs, globals) {
    const results = [];
    if (!globals) return results;
    for (const tech of techs) {
      if (!tech.js) continue;
      for (const [varName, versionProp] of Object.entries(tech.js)) {
        const info = globals[varName];
        if (!info || !info.exists) continue;
        const entry = { name: tech.name, category: tech.category, method: 'js' };
        if (versionProp && info.version) {
          entry.version = info.version;
        }
        results.push(entry);
        break;
      }
    }
    return results;
  }

  /**
   * Merge detection results, deduplicating by tech name.
   * Keeps the first detected version and all methods.
   * @param {...Object[]} resultArrays - arrays of detection results
   * @returns {Object[]} merged, deduplicated results
   */
  function mergeResults(...resultArrays) {
    const map = new Map();
    for (const arr of resultArrays) {
      for (const r of arr) {
        const existing = map.get(r.name);
        if (existing) {
          if (!existing.version && r.version) existing.version = r.version;
          if (!existing.methods.includes(r.method)) existing.methods.push(r.method);
        } else {
          map.set(r.name, {
            name: r.name,
            category: r.category,
            version: r.version || null,
            methods: [r.method]
          });
        }
      }
    }
    return Array.from(map.values());
  }

  return {
    testPattern,
    detectScripts,
    detectDom,
    detectMeta,
    detectHtml,
    detectHeaders,
    detectJs,
    mergeResults
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = TechDetector;
}
