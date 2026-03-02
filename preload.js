'use strict';

const { contextBridge, ipcRenderer } = require('electron');

const _SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';

// Apply privacy protections before any page script runs
(function hardenPrivacy() {
  try {
    const _hn = (window.location.hostname || '').toLowerCase().replace(/^www\./, '');

    // Sites that need full browser capabilities — skip heavy fingerprinting
    const _bypass = [
      'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'musical.ly',
      'spotify.com', 'open.spotify.com', 'scdn.co', 'spotifycdn.com',
      'soundcloud.com',
      'netflix.com', 'hulu.com', 'disneyplus.com', 'primevideo.com',
      'youtube.com', 'youtu.be',
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
        if (!window.chrome) window.chrome = {};
        window.chrome.app = { isInstalled: false, InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' }, RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }, getDetails: () => null, getIsInstalled: () => false, installState: (cb) => cb('not_installed'), runningState: () => 'cannot_run' };
        window.chrome.runtime = { id: undefined, connect: () => ({ postMessage(){}, onMessage:{ addListener(){} }, disconnect(){} }), sendMessage: () => {}, onMessage: { addListener(){} }, onConnect: { addListener(){} } };
        window.chrome.csi = () => ({ startE: Date.now(), onloadT: Date.now(), pageT: 1000, tran: 15 });
        window.chrome.loadTimes = () => ({ requestTime: Date.now()/1000, startLoadTime: Date.now()/1000, commitLoadTime: Date.now()/1000, finishDocumentLoadTime: Date.now()/1000, finishLoadTime: Date.now()/1000, firstPaintTime: Date.now()/1000, firstPaintAfterLoadTime: 0, navigationType: 'Other', wasFetchedViaSpdy: false, wasNpnNegotiated: false, npnNegotiatedProtocol: 'unknown', wasAlternateProtocolAvailable: false, connectionInfo: 'http/1.1' });
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
          { brand: 'Google Chrome', version: '134' },
          { brand: 'Chromium', version: '134' },
        ];
        Object.defineProperty(navigator, 'userAgentData', {
          get: () => ({
            brands: _uaBrands,
            mobile: false,
            platform: 'Windows',
            getHighEntropyValues: () => Promise.resolve({
              architecture: 'x86', bitness: '64',
              brands: _uaBrands,
              fullVersionList: [{ brand: 'Google Chrome', version: '134.0.6998.89' }],
              mobile: false, model: '',
              platform: 'Windows', platformVersion: '10.0.0',
              uaFullVersion: '134.0.6998.89',
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