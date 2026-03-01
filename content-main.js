/**
 * content-main.js — Runs in MAIN world to probe JS globals.
 * Posts results back to the content script via window.postMessage.
 */
(() => {
  'use strict';

  const JS_PROBES = {
    // JS Frameworks
    '__REACT_DEVTOOLS_GLOBAL_HOOK__': '',
    '__VUE__': '',
    'Vue': '',
    'ng': '',
    '__svelte': '',
    '__NEXT_DATA__': '',
    '__NUXT__': '',
    '$nuxt': '',
    '___gatsby': '',
    '__remixContext': '',
    'Ember': '',
    'Backbone': '',
    'Alpine': '',
    'htmx': '',
    // JS Libraries
    'jQuery': 'fn.jquery',
    '_': 'VERSION',
    'axios': '',
    'moment': 'version',
    'THREE': 'REVISION',
    'd3': 'version',
    // CSS Frameworks (JS parts)
    'bootstrap': '',
    'Foundation': 'version',
    'M': 'toast',
    // CMS
    'Shopify': '',
    'wixBiSession': '',
    'SQUARESPACE_CONTEXT': '',
    'Drupal': '',
    // Analytics
    'ga': '',
    'gtag': '',
    'GoogleAnalyticsObject': '',
    'google_tag_manager': '',
    'fbq': '',
    'hj': '',
    'hjSiteSettings': '',
    'mixpanel': '',
    // Build
    'webpackJsonp': '',
    'webpackChunk': '',
    // Security
    'grecaptcha': '',
    'hcaptcha': ''
  };

  function resolveProperty(obj, path) {
    if (!path || !obj) return undefined;
    const parts = path.split('.');
    let current = obj;
    for (const part of parts) {
      if (current == null) return undefined;
      current = current[part];
    }
    return current;
  }

  function probeGlobals() {
    const results = {};
    for (const [varName, versionPath] of Object.entries(JS_PROBES)) {
      try {
        const val = window[varName];
        if (val !== undefined && val !== null) {
          const entry = { exists: true };
          if (versionPath) {
            const ver = resolveProperty(val, versionPath);
            if (ver !== undefined && ver !== null) {
              entry.version = String(ver);
            }
          }
          results[varName] = entry;
        }
      } catch (err) {
        // Access denied or error, skip silently
      }
    }
    return results;
  }

  // Small delay to let frameworks initialize
  setTimeout(() => {
    try {
      const globals = probeGlobals();
      window.postMessage({
        type: 'TECH_DETECTOR_JS_PROBE',
        globals
      }, '*');
    } catch (err) {
      console.error('[Tech Detector] Failed to probe globals:', err.message);
    }
  }, 500);
})();
