/**
 * content.js — Content script for Tech Detector_Enhanced.
 * Runs in ISOLATED world. Performs DOM, meta, scripts, and HTML detection.
 * Receives JS globals from content-main.js via postMessage.
 */
(() => {
  'use strict';

  let technologies = null;
  let jsGlobals = null;
  let detectionSent = false;

  // Listen for JS probe results from MAIN world
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    if (event.data && event.data.type === 'TECH_DETECTOR_JS_PROBE') {
      jsGlobals = event.data.globals;
      runDetection();
    }
  });

  // Fallback: inject script for browsers without world: "MAIN" support
  function injectProbeScript() {
    try {
      const script = document.createElement('script');
      script.src = (typeof browser !== 'undefined' ? browser : chrome).runtime.getURL('content-main.js');
      (document.head || document.documentElement).appendChild(script);
      script.onload = () => script.remove();
    } catch (err) {
      console.warn('[Tech Detector_Enhanced] Script injection failed:', err.message);
      jsGlobals = {};
      runDetection();
    }
  }

  // Load technologies DB
  async function loadTechnologies() {
    try {
      const url = (typeof browser !== 'undefined' ? browser : chrome).runtime.getURL('technologies.json');
      const resp = await fetch(url);
      technologies = await resp.json();
    } catch (err) {
      console.error('[Tech Detector_Enhanced] Failed to load technologies.json:', err.message);
    }
  }

  // Collect signals from the page
  function collectSignals() {
    // Script src attributes
    const scriptSrcs = [];
    document.querySelectorAll('script[src]').forEach(el => {
      scriptSrcs.push(el.getAttribute('src'));
    });

    // Meta tags
    const metaTags = {};
    document.querySelectorAll('meta[name], meta[property]').forEach(el => {
      const name = (el.getAttribute('name') || el.getAttribute('property') || '').toLowerCase();
      const content = el.getAttribute('content') || '';
      if (name) metaTags[name] = content;
    });

    // DOM query function
    const querySelectorFn = (selector) => {
      return document.querySelector(selector) !== null;
    };

    // HTML source (first 50KB)
    const html = document.documentElement.outerHTML.substring(0, 50000);

    return { scriptSrcs, metaTags, querySelectorFn, html };
  }

  function runDetection() {
    if (detectionSent || !technologies) return;
    if (jsGlobals === null) return;

    detectionSent = true;

    const techs = technologies.technologies;
    const { scriptSrcs, metaTags, querySelectorFn, html } = collectSignals();

    const scriptResults = TechDetector.detectScripts(techs, scriptSrcs);
    const domResults = TechDetector.detectDom(techs, querySelectorFn);
    const metaResults = TechDetector.detectMeta(techs, metaTags);
    const htmlResults = TechDetector.detectHtml(techs, html);
    const jsResults = TechDetector.detectJs(techs, jsGlobals);

    const merged = TechDetector.mergeResults(
      scriptResults, domResults, metaResults, htmlResults, jsResults
    );

    // Send results to background
    const api = typeof browser !== 'undefined' ? browser : chrome;
    api.runtime.sendMessage({
      type: 'DETECTION_RESULT',
      detections: merged,
      url: window.location.href
    }).catch((err) => {
      console.warn('[Tech Detector_Enhanced] Failed to send detection results:', err.message);
    });
  }

  // Initialize
  async function init() {
    await loadTechnologies();

    // Timeout for JS globals: if MAIN world script doesn't report in 2s, proceed without it
    setTimeout(() => {
      if (jsGlobals === null) {
        jsGlobals = {};
        runDetection();
      }
    }, 2000);

    if (jsGlobals !== null) {
      runDetection();
    }
  }

  init();
})();
