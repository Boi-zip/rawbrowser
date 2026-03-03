'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const _SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36';

// Apply privacy protections before any page script runs
(function hardenPrivacy() {
  try {
    const _hn = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

    // Sites that need full browser capabilities — skip heavy fingerprinting
    const _bypass = [
      // Google — all sign-in, auth, and service domains MUST be here or Google
      // detects the empty plugins/permissions fingerprint and blocks login.
      'google.com', 'googleapis.com', 'googleusercontent.com',
      'gstatic.com', 'gmail.com', 'accounts.google.com',
      // Media / streaming sites that need all Chrome APIs
      'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'musical.ly',
      'spotify.com', 'open.spotify.com', 'scdn.co', 'spotifycdn.com',
      'soundcloud.com',
      'netflix.com', 'hulu.com', 'disneyplus.com', 'primevideo.com',
      'youtube.com', 'youtu.be',
      // Microsoft / Apple sign-in flows
      'microsoft.com', 'live.com', 'microsoftonline.com',
      'apple.com', 'appleid.apple.com',
      // Facebook / Instagram sign-in
      'facebook.com', 'instagram.com', 'fbcdn.net',
    ];
    const _isBypass = _bypass.some(h => _hn === h || _hn.endsWith('.' + h));

    // ── WebRTC IP leak protection — skip for media/streaming sites ──────────
    // Chromium-level protection is set via commandLine switches in main.js.
    // This JS layer adds defence-in-depth for non-bypass sites only.
    if (!_isBypass) {
      try {
        if (window.RTCPeerConnection) {
          const _OrigRTC = window.RTCPeerConnection;
          function _SafeRTC(config, constraints) {
            const safe = config ? { ...config, iceTransportPolicy: 'relay' }
                                 : { iceTransportPolicy: 'relay' };
            return new _OrigRTC(safe, constraints);
          }
          _SafeRTC.prototype = _OrigRTC.prototype;
          Object.defineProperty(window, 'RTCPeerConnection',
            { value: _SafeRTC, writable: false, configurable: false });
          if ('webkitRTCPeerConnection' in window)
            Object.defineProperty(window, 'webkitRTCPeerConnection',
              { value: _SafeRTC, writable: false, configurable: false });
        }
      } catch {}
    }

    if (_isBypass) {
      // Minimal spoofing only — ensure these sites see a real Chrome browser
      try {
        Object.defineProperty(navigator, 'webdriver',  { get: () => false, configurable: true });
        Object.defineProperty(navigator, 'userAgent',  { get: () => _SPOOF_UA, configurable: true });
        Object.defineProperty(navigator, 'vendor',     { get: () => 'Google Inc.', configurable: true });
        Object.defineProperty(navigator, 'platform',   { get: () => 'Win32', configurable: true });
        Object.defineProperty(navigator, 'language',   { get: () => 'en-US', configurable: true });
        Object.defineProperty(navigator, 'languages',  { get: () => ['en-US', 'en'], configurable: true });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: true });
        // Chrome 136 has a built-in PDF viewer — Electron doesn't, so we must spoof this
        try { Object.defineProperty(navigator, 'pdfViewerEnabled', { get: () => true, configurable: true }); } catch {}
        // Override userAgentData — CRITICAL: without this Electron exposes its own
        // brands list (containing "Electron") even when the UA string says Chrome.
        // Google and other sign-in providers read navigator.userAgentData.brands
        // directly to detect non-Chrome browsers.
        if ('userAgentData' in navigator) {
          try {
            const _bypassBrands = [
              { brand: 'Not A(Brand', version: '99' },
              { brand: 'Google Chrome', version: '136' },
              { brand: 'Chromium', version: '136' },
            ];
            Object.defineProperty(navigator, 'userAgentData', {
              get: () => ({
                brands: _bypassBrands,
                mobile: false,
                platform: 'Windows',
                getHighEntropyValues: () => Promise.resolve({
                  architecture: 'x86', bitness: '64',
                  brands: _bypassBrands,
                  fullVersionList: [
                    { brand: 'Google Chrome', version: '136.0.7103.116' },
                    { brand: 'Chromium',      version: '136.0.7103.116' },
                    { brand: 'Not A(Brand',   version: '99.0.0.0' },
                  ],
                  mobile: false, model: '',
                  platform: 'Windows', platformVersion: '10.0.0',
                  uaFullVersion: '136.0.7103.116',
                }),
                toJSON: () => ({ brands: _bypassBrands, mobile: false, platform: 'Windows' }),
              }),
              configurable: true,
            });
          } catch {}
        }
        if (!window.chrome) window.chrome = {};
        window.chrome.app = { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }, getDetails: () => null, getIsInstalled: () => false, installState: (cb) => cb('not_installed'), runningState: () => 'cannot_run' };
        window.chrome.runtime = { id: undefined, connect: () => ({ postMessage(){}, onMessage:{ addListener(){} }, disconnect(){} }), sendMessage: () => {}, onMessage: { addListener(){} }, onConnect: { addListener(){} } };
        window.chrome.csi = () => ({ startE: Date.now(), onloadT: Date.now(), pageT: 1000, tran: 15 });
        window.chrome.loadTimes = () => ({ requestTime: Date.now()/1000, startLoadTime: Date.now()/1000, commitLoadTime: Date.now()/1000, finishDocumentLoadTime: Date.now()/1000, finishLoadTime: Date.now()/1000, firstPaintTime: Date.now()/1000, firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: false, wasNpnNegotiated: false, npnNegotiatedProtocol: 'unknown', wasAlternateProtocolAvailable: false, connectionInfo: 'http/1.1' });
        // chrome.storage is accessed by extensions and sign-in helpers
        if (!window.chrome.storage) window.chrome.storage = { local: { get: (_k, cb) => cb && cb({}), set: (_d, cb) => cb && cb() }, sync: { get: (_k, cb) => cb && cb({}), set: (_d, cb) => cb && cb() }, onChanged: { addListener: () => {} } };
      } catch {}
      return; // Don't apply full fingerprint hardening to these sites
    }

    // ── Full fingerprint hardening for all other sites ──────────────────────

    // Remove webdriver flag
    Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: false });

    // Canvas fingerprint noise
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    function _addNoise(data) {
      for (let i = 0; i < data.length; i += 4) {
        data[i]   = Math.min(255, Math.max(0, data[i]   + ((Math.random() * 2 - 1) | 0)));
        data[i+1] = Math.min(255, Math.max(0, data[i+1] + ((Math.random() * 2 - 1) | 0)));
        data[i+2] = Math.min(255, Math.max(0, data[i+2] + ((Math.random() * 2 - 1) | 0)));
      }
      return data;
    }
    HTMLCanvasElement.prototype.toDataURL = function(...a) {
      const ctx = this.getContext('2d');
      if (ctx) { try { const d = ctx.getImageData(0,0,this.width,this.height); _addNoise(d.data); ctx.putImageData(d,0,0); } catch {} }
      return _origToDataURL.apply(this, a);
    };

    // WebGL vendor/renderer spoofing
    const _patchWebGL = (cls) => {
      if (typeof cls === 'undefined') return;
      const orig = cls.prototype.getParameter;
      cls.prototype.getParameter = function(p) {
        if (p === 37445) return 'Intel Inc.';
        if (p === 37446) return 'Intel Iris OpenGL Engine';
        return orig.call(this, p);
      };
    };
    _patchWebGL(WebGLRenderingContext);
    if (typeof WebGL2RenderingContext !== 'undefined') _patchWebGL(WebGL2RenderingContext);

    // AudioContext noise
    if (typeof AudioBuffer !== 'undefined') {
      const _origGCD = AudioBuffer.prototype.getChannelData;
      AudioBuffer.prototype.getChannelData = function(...a) {
        const d = _origGCD.apply(this, a);
        for (let i = 0; i < d.length; i += 100) d[i] += Math.random() * 0.0001 - 0.00005;
        return d;
      };
    }

    // Block Battery API
    if (navigator.getBattery) {
      Object.defineProperty(navigator, 'getBattery', {
        value: () => Promise.reject(new Error('Blocked')), writable: false, configurable: false,
      });
    }

    // Spoof hardware
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8, configurable: false });
    if ('deviceMemory' in navigator) {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 8, configurable: false });
    }

    // Empty plugins/mimeTypes
    Object.defineProperty(navigator, 'plugins',   { get: () => [], configurable: false });
    Object.defineProperty(navigator, 'mimeTypes', { get: () => [], configurable: false });

    // Block network info
    if ('connection' in navigator) {
      Object.defineProperty(navigator, 'connection', { get: () => undefined, configurable: false });
    }

    // Block media devices enumeration
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      const origEnumerate = navigator.mediaDevices.enumerateDevices;
      navigator.mediaDevices.enumerateDevices = function() {
        return origEnumerate.call(this).then(() => []);
      };
    }

    // Stub permissions API — return 'denied' rather than throwing (broken sites reject on error)
    if (navigator.permissions && navigator.permissions.query) {
      navigator.permissions.query = function(desc) {
        return Promise.resolve({ state: 'denied', onchange: null });
      };
    }

    // Spoof navigator identity to match Chrome
    try {
      Object.defineProperty(navigator, 'userAgent',  { get: () => _SPOOF_UA, configurable: false });
      Object.defineProperty(navigator, 'vendor',     { get: () => 'Google Inc.', configurable: false });
      Object.defineProperty(navigator, 'platform',   { get: () => 'Win32', configurable: false });
      Object.defineProperty(navigator, 'language',   { get: () => 'en-US', configurable: false });
      Object.defineProperty(navigator, 'languages',  { get: () => Object.freeze(['en-US', 'en']), configurable: false });
      Object.defineProperty(navigator, 'doNotTrack', { get: () => '1', configurable: false });
    } catch {}

    // Block window.name persistence (cross-origin tracking vector)
    try {
      Object.defineProperty(window, 'name', {
        get: () => '', set: () => {}, configurable: false,
      });
    } catch {}

    // Block Beacon API (used for analytics even after page unload)
    if (navigator.sendBeacon) {
      Object.defineProperty(navigator, 'sendBeacon', {
        value: () => true, writable: false, configurable: false,
      });
    }

    // Spoof screen dimensions to a common resolution (1920x1080)
    try {
      ['width','height','availWidth','availHeight'].forEach((k, i) => {
        const vals = [1920, 1080, 1920, 1080];
        Object.defineProperty(screen, k, { get: () => vals[i], configurable: false });
      });
      Object.defineProperty(screen, 'colorDepth',  { get: () => 24, configurable: false });
      Object.defineProperty(screen, 'pixelDepth',  { get: () => 24, configurable: false });
    } catch {}

    // Spoof navigator.userAgentData (Client Hints API — exposes detailed OS/browser info)
    if ('userAgentData' in navigator) {
      try {
        const _uaBrands = [
          { brand: 'Not A(Brand', version: '99' },
          { brand: 'Google Chrome', version: '136' },
          { brand: 'Chromium', version: '136' },
        ];
        Object.defineProperty(navigator, 'userAgentData', {
          get: () => ({
            brands: _uaBrands,
            mobile: false,
            platform: 'Windows',
            getHighEntropyValues: () => Promise.resolve({
              architecture: 'x86', bitness: '64',
              brands: _uaBrands,
              fullVersionList: [{ brand: 'Google Chrome', version: '136.0.7103.116' }, { brand: 'Chromium', version: '136.0.7103.116' }, { brand: 'Not A(Brand', version: '99.0.0.0' }],
              mobile: false, model: '',
              platform: 'Windows', platformVersion: '10.0.0',
              uaFullVersion: '136.0.7103.116',
            }),
            toJSON: () => ({ brands: _uaBrands, mobile: false, platform: 'Windows' }),
          }),
          configurable: false,
        });
      } catch {}
    }

    // Prevent touch-device detection (fingerprinting via maxTouchPoints)
    try {
      Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0, configurable: false });
    } catch {}

    // Block speechSynthesis voice enumeration (unique voice list = fingerprint)
    if ('speechSynthesis' in window) {
      try {
        Object.defineProperty(window, 'speechSynthesis', {
          get: () => ({
            getVoices: () => [], speak: () => {}, cancel: () => {},
            pause: () => {}, resume: () => {}, pending: false,
            speaking: false, paused: false,
            addEventListener: () => {}, removeEventListener: () => {},
            dispatchEvent: () => false,
          }),
          configurable: false,
        });
      } catch {}
    }

    // Block keyboard layout fingerprinting (navigator.keyboard)
    if ('keyboard' in navigator) {
      try {
        Object.defineProperty(navigator, 'keyboard', { get: () => undefined, configurable: false });
      } catch {}
    }

    // Neutralize window.opener (prevents tab-napping: opener can redirect parent tab)
    try { if (window.opener !== null) window.opener = null; } catch {}

    // Freeze devicePixelRatio to 1 (reveals display scaling/device type)
    try {
      Object.defineProperty(window, 'devicePixelRatio', { get: () => 1, configurable: false });
    } catch {}

  } catch (e) {
    console.debug('[Raw] Preload error:', e.message);
  }
})();

// ── Media keep-alive guard — injected into the main world before any page script ──
// Uses a <script> element so it runs in the page's JS world (not the isolated
// preload world), meaning our IntersectionObserver and pause overrides are
// installed before YouTube / TikTok / etc. create their observer instances.
// window._rbPanelOpen is set by PANEL_KEEP_ALIVE_JS (main process) when a
// toolbar panel opens, and cleared by PANEL_RESTORE_ALIVE_JS when it closes.
(function injectMediaGuard() {
  try {
    const script = document.createElement('script');
    script.textContent = `(function(){
  if (window._rbGuardInstalled) return;
  window._rbGuardInstalled = true;
  window._rbPanelOpen = false;

  // Wrap IntersectionObserver: while _rbPanelOpen, report every entry as
  // fully visible so YouTube/TikTok players never call .pause() on scroll-out.
  if (window.IntersectionObserver) {
    var _OrigIO = window.IntersectionObserver;
    window.IntersectionObserver = function(cb, opts) {
      return new _OrigIO(function(entries, obs) {
        if (window._rbPanelOpen) {
          entries = entries.map(function(e) {
            return { boundingClientRect:e.boundingClientRect, intersectionRatio:1,
              intersectionRect:e.boundingClientRect, isIntersecting:true,
              rootBounds:e.rootBounds, target:e.target, time:e.time };
          });
        }
        return cb(entries, obs);
      }, opts);
    };
    try { window.IntersectionObserver.prototype = _OrigIO.prototype; } catch(e){}
  }

  // Wrap HTMLVideoElement.pause: drop automatic pauses while panel is open.
  var _origPause = HTMLVideoElement.prototype.pause;
  HTMLVideoElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origPause.call(this);
  };

  // Swallow AbortErrors from play() calls that race with blocked pauses.
  var _origPlay = HTMLVideoElement.prototype.play;
  HTMLVideoElement.prototype.play = function() {
    var p = _origPlay.call(this);
    if (p && p.catch) p.catch(function(){});
    return p;
  };
})()`;
    // Insert before <head> so it runs before any other scripts
    (document.head || document.documentElement).prepend(script);
    script.remove(); // clean up the element after execution
  } catch (e) {}
})();

// ── Autofill detection ────────────────────────────────────────────────────────
// Watches for login forms and requests credential autofill from the vault.
(function() {
  let _afTimer = null;

  function _hasPasswordInput() {
    return !!document.querySelector('input[type="password"]');
  }

  function _tryQuery() {
    clearTimeout(_afTimer);
    _afTimer = setTimeout(function() {
      if (_hasPasswordInput()) {
        ipcRenderer.send('autofill:query', { domain: window.location.hostname });
      }
    }, 800);
  }

  // On initial page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _tryQuery, { once: true });
  } else {
    _tryQuery();
  }

  // Watch for SPA-style dynamic form injection
  if (window.MutationObserver) {
    var _mo = new MutationObserver(function(_mutations) {
      if (_hasPasswordInput()) _tryQuery();
    });
    _mo.observe(document.documentElement, { childList: true, subtree: true });
  }

  // Fill fields when renderer sends back credentials
  ipcRenderer.on('autofill:fill', function(_e, data) {
    try {
      var pwInputs  = Array.from(document.querySelectorAll('input[type="password"]'));
      var userInputs = Array.from(document.querySelectorAll(
        'input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[id*="user"], input[id*="email"]'
      ));

      // Use native setter so React/Vue/Angular re-render
      var nativeInputSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
      var fire = function(el, val) {
        nativeInputSetter.call(el, val);
        el.dispatchEvent(new Event('input',  { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      };

      if (userInputs.length && data.username) fire(userInputs[0], data.username);
      if (pwInputs.length   && data.password) fire(pwInputs[0],   data.password);
    } catch(e) {}
  });
})();

// Expose minimal API to page context
contextBridge.exposeInMainWorld('raw', {
  platform: process.platform,
  getSettings: () => ipcRenderer.invoke('get-settings'),
  on: (channel, cb) => {
    const valid = ['toast', 'settings:set', 'downloads:update'];
    if (valid.includes(channel)) ipcRenderer.on(channel, (_e, ...a) => cb(...a));
  },
  removeAllListeners: ch => ipcRenderer.removeAllListeners(ch),
});