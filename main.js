'use strict';

const {
  app, BrowserWindow, BrowserView,
  ipcMain, dialog, shell, session, Menu, clipboard,
} = require('electron');
const path               = require('path');
const fs                 = require('fs');
const https              = require('https');
const { spawn }          = require('child_process');
const { pathToFileURL }  = require('url');
const os                 = require('os');
const { shouldBlock }    = require('./blocklist.js');

// Domains never blocked regardless of settings (needed for site functionality)
const BUILTIN_WHITELIST = [
  'tiktok.com','tiktokv.com','tiktokcdn.com','tiktokcdn-us.com',
  'ttwstatic.com','byteoversea.com','ibytedtos.com','ibyteimg.com',
  'musical.ly','snssdk.com','bdurl.net',
  // Spotify — CDN, auth, and DRM license domains required for playback
  'spotify.com','scdn.co','spotifycdn.com','spotifycdn.net',
  'pscdn.co','spotilocal.com','audio-ak-spotify-com.akamaized.net',
  // Google — ALL auth, sign-in, and service domains must preserve headers intact.
  // Google's OAuth flow validates Referer, Sec-Fetch-*, and other headers across
  // redirects between these domains. Any stripping triggers the
  // "This browser may not be secure" block on accounts.google.com.
  'google.com','accounts.google.com','apis.google.com',
  'googleapis.com','googleusercontent.com','gstatic.com',
  'gmail.com','youtube.com','ytimg.com','ggpht.com',
  'google-analytics.com','googletagmanager.com',
];

if (process.platform === 'win32') app.setAppUserModelId('com.raw.browser');

// Remove the automation flag Electron sets by default — Google checks this
// to determine if the browser is automated/non-standard. Must be set before
// any window is created (commandLine switches are read at startup).
app.commandLine.appendSwitch('disable-blink-features', 'AutomationControlled');

// ── ENHANCED PRIVACY: Prevent IP leaks through WebRTC ───────────────────────
app.commandLine.appendSwitch('disable-webrtc-ip-handling');
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'default_public_interface_only');
app.commandLine.appendSwitch('webrtc-ip-handling-policy', 'disable_non_proxied_udp');

// Disable geolocation, microphone, camera by default
app.commandLine.appendSwitch('disable-geolocation');
app.commandLine.appendSwitch('disable-web-notifications');

// ── Widevine CDM (enables DRM for Spotify, Netflix, etc.) ─────────────────────
(function tryLoadWidevine() {
  function _tryDir(base) {
    // base is e.g. Chrome's or Edge's "Application" folder
    if (!fs.existsSync(base)) return false;
    const versions = fs.readdirSync(base)
      .filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v))
      .sort((a, b) => {
        const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
        for (let i = 0; i < 4; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i]; }
        return 0;
      });
    for (const ver of versions) {
      const cdmPath = path.join(base, ver, 'WidevineCdm', '_platform_specific', 'win_x64', 'widevinecdm.dll');
      const manifest = path.join(base, ver, 'WidevineCdm', 'manifest.json');
      if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
        const mf = JSON.parse(fs.readFileSync(manifest, 'utf8'));
        app.commandLine.appendSwitch('widevine-cdm-path', cdmPath);
        app.commandLine.appendSwitch('widevine-cdm-version', mf.version || '');
        return true;
      }
    }
    return false;
  }

  function _tryUserDataDir(base) {
    // Modern Chrome/Edge stores WidevineCdm under User Data\WidevineCdm\<version>\
    // e.g. %LOCALAPPDATA%\Google\Chrome\User Data\WidevineCdm\4.10.2557.0\
    if (!fs.existsSync(base)) return false;
    const versions = fs.readdirSync(base)
      .filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v))
      .sort((a, b) => {
        const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
        for (let i = 0; i < 4; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i]; }
        return 0;
      });
    for (const ver of versions) {
      const cdmPath = path.join(base, ver, '_platform_specific', 'win_x64', 'widevinecdm.dll');
      const manifest = path.join(base, ver, 'manifest.json');
      if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
        try {
          const mf = JSON.parse(fs.readFileSync(manifest, 'utf8'));
          app.commandLine.appendSwitch('widevine-cdm-path', cdmPath);
          app.commandLine.appendSwitch('widevine-cdm-version', mf.version || ver);
          return true;
        } catch { return false; }
      }
    }
    return false;
  }

  try {
    if (process.platform === 'win32') {
      const local = process.env.LOCALAPPDATA || '';
      const prog  = process.env.PROGRAMFILES || 'C:\\Program Files';
      const prog86 = process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)';
      // Modern Chrome/Edge (v120+) keeps WidevineCdm in User Data, not Application
      const userDataCandidates = [
        path.join(local, 'Google', 'Chrome', 'User Data', 'WidevineCdm'),
        path.join(local, 'Microsoft', 'Edge', 'User Data', 'WidevineCdm'),
        path.join(prog,  'Google', 'Chrome', 'User Data', 'WidevineCdm'),
      ];
      let found = false;
      for (const c of userDataCandidates) { if (_tryUserDataDir(c)) { found = true; break; } }
      // Fallback: legacy Application\<ver>\WidevineCdm layout (older Chrome/Edge installs)
      if (!found) {
        const candidates = [
          path.join(local,  'Google', 'Chrome', 'Application'),
          path.join(local,  'Microsoft', 'Edge', 'Application'),
          path.join(prog,   'Google', 'Chrome', 'Application'),
          path.join(prog86, 'Google', 'Chrome', 'Application'),
          path.join(prog,   'Microsoft', 'Edge', 'Application'),
        ];
        for (const c of candidates) { if (_tryDir(c)) break; }
      }
    } else if (process.platform === 'darwin') {
      // macOS: try Chrome (arm64 + x64), then Brave
      const _tryMacCdm = (cdmPath, manifestPath) => {
        if (!fs.existsSync(cdmPath) || !fs.existsSync(manifestPath)) return false;
        try {
          const mf = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
          app.commandLine.appendSwitch('widevine-cdm-path', cdmPath);
          app.commandLine.appendSwitch('widevine-cdm-version', mf.version || '');
          return true;
        } catch { return false; }
      };
      const _macBase = (app_name, fw_name) =>
        `/Applications/${app_name}.app/Contents/Frameworks/${fw_name}.framework/Versions/Current/Libraries/WidevineCdm`;
      const _macChromeBase = _macBase('Google Chrome', 'Google Chrome Framework');
      const _macBraveBase  = _macBase('Brave Browser', 'Brave Browser Framework');
      [
        [_macChromeBase + '/_platform_specific/mac_arm64/libwidevinecdm.dylib', _macChromeBase + '/manifest.json'],
        [_macChromeBase + '/_platform_specific/mac_x64/libwidevinecdm.dylib',   _macChromeBase + '/manifest.json'],
        [_macBraveBase  + '/_platform_specific/mac_arm64/libwidevinecdm.dylib',  _macBraveBase  + '/manifest.json'],
        [_macBraveBase  + '/_platform_specific/mac_x64/libwidevinecdm.dylib',    _macBraveBase  + '/manifest.json'],
      ].some(([cdm, mf]) => _tryMacCdm(cdm, mf));
    } else if (process.platform === 'linux') {
      // Linux: search versioned WidevineCdm dirs under Chrome/Chromium user + system paths
      const home = process.env.HOME || '';
      function _tryLinuxCdmDir(base) {
        if (!fs.existsSync(base)) return false;
        const versions = fs.readdirSync(base)
          .filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v))
          .sort((a, b) => {
            const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
            for (let i = 0; i < 4; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i]; }
            return 0;
          });
        for (const ver of versions) {
          const cdmPath = path.join(base, ver, '_platform_specific', 'linux_x64', 'libwidevinecdm.so');
          const manifest = path.join(base, ver, 'manifest.json');
          if (fs.existsSync(cdmPath) && fs.existsSync(manifest)) {
            try {
              const mf = JSON.parse(fs.readFileSync(manifest, 'utf8'));
              app.commandLine.appendSwitch('widevine-cdm-path', cdmPath);
              app.commandLine.appendSwitch('widevine-cdm-version', mf.version || '');
              return true;
            } catch {}
          }
        }
        return false;
      }
      const linuxCandidates = [
        path.join(home, '.config', 'google-chrome', 'WidevineCdm'),
        path.join(home, '.config', 'chromium', 'WidevineCdm'),
        path.join(home, '.var', 'app', 'com.google.Chrome', 'config', 'google-chrome', 'WidevineCdm'),
        path.join(home, '.var', 'app', 'org.chromium.Chromium', 'config', 'chromium', 'WidevineCdm'),
        path.join(home, 'snap', 'google-chrome', 'current', '.config', 'google-chrome', 'WidevineCdm'),
        '/opt/google/chrome/WidevineCdm',
        '/usr/lib/chromium/WidevineCdm',
        '/usr/lib/chromium-browser/WidevineCdm',
      ];
      for (const c of linuxCandidates) { if (_tryLinuxCdmDir(c)) break; }
    }
  } catch { /* Widevine unavailable — silently continue */ }
})();

// Allow audio/video autoplay without user gesture (needed for Music Player)
app.commandLine.appendSwitch('autoplay-policy', 'no-user-gesture-required');
// Enable hardware-accelerated media key handling + platform EME — all features combined
// into ONE appendSwitch call because Chromium only honours the LAST --enable-features
// value; separate calls silently overwrite each other.
if (process.platform === 'win32') {
  app.commandLine.appendSwitch('enable-features', 'HardwareMediaKeyHandling,MediaSessionService,PlatformEncryptedMediaFoundation');
} else {
  app.commandLine.appendSwitch('enable-features', 'HardwareMediaKeyHandling,MediaSessionService');
}
// Prevent Chromium from EVER suspending background renderer processes or their media.
// This is the definitive fix for videos/audio pausing when a BV is detached from the window.
// JS-level overrides (visibility, blur, etc.) can race with native Chromium scheduler events;
// these flags disable the scheduler behaviour entirely at the process level.
app.commandLine.appendSwitch('disable-renderer-backgrounding');
app.commandLine.appendSwitch('disable-background-media-suspend');

// ── Default browser + external URL handling ──────────────────────────────────
// Register RAW as a capable handler for http/https at the OS level.
// On Windows 10/11 this writes the registry entries; user still selects via Settings.
// On macOS this may set it directly depending on OS version.
app.setAsDefaultProtocolClient('https');
app.setAsDefaultProtocolClient('http');

// Extract a navigable URL from a process argv array (set as default browser or open-with).
function getArgUrl(argv) {
  for (const a of (argv || []).slice(1)) {
    if (/^https?:\/\//i.test(a)) return a;
    if (/^file:\/\//i.test(a))   return a;
    // Windows: file path passed directly (e.g. double-click .html)
    if (/\.(html?|xhtml|pdf)$/i.test(a)) {
      try { if (fs.existsSync(a)) return pathToFileURL(a).href; } catch {}
    }
  }
  return null;
}

// Single-instance lock: if RAW is already running and an external link is clicked,
// forward the URL to the existing window instead of opening a second instance.
const _gotSingleLock = app.requestSingleInstanceLock();
if (!_gotSingleLock) { app.quit(); }
app.on('second-instance', (_, argv) => {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.focus();
  const url = getArgUrl(argv);
  if (url) createTab(url, true);
});

// macOS: link clicked in another app while RAW is already running
let _pendingExtUrl = null;
app.on('open-url', (event, url) => {
  event.preventDefault();
  if (win) createTab(url, true);
  else _pendingExtUrl = url;
});

const SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const SPOOF_UA_HINTS = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';

// ── Global UA fallback ─────────────────────────────────────────────────────────
// The deepest possible override — covers every WebContents that has NOT had
// setUserAgent() called explicitly (service workers, pre-flight auth checks,
// non-partitioned popup windows, etc.). Must be set BEFORE app.whenReady().
app.userAgentFallback = SPOOF_UA;

// Set the UA at the Chromium process level — applies to every renderer, service
// worker, and sub-frame before any JS runs, overriding Electron's own binary string.
app.commandLine.appendSwitch('user-agent', SPOOF_UA);

// ── Block WebAuthn / Passkeys at the Chromium level ──────────────────────────
// Prevents the Windows Hello / native FIDO2 dialog from appearing on Google,
// Microsoft, or any other site. JS-level credential stubs in preload.js give
// sites a graceful "not supported" signal; these flags ensure the underlying
// Chromium authenticator subsystem never even initialises.
// Combine ALL disable-features into one call — Chromium only honours the last value.
// Also disable ElectronNonClientWindowFromFrame — this Electron-specific feature
// exposes internals that detection scripts can query.
app.commandLine.appendSwitch('disable-features', 'WebRtcHideLocalIpsWithMdns,WebAuthentication,WebAuthenticationCableSecondFactor,WebAuthenticationPasskeysInBrowserWindow,WebAuthenticationRemoteDesktopSupport');

// ── Anti-bot detection flags ─────────────────────────────────────────────────
// Remove Electron-specific infobars / first-run markers that differ from Chrome.
app.commandLine.appendSwitch('disable-infobars');
app.commandLine.appendSwitch('no-first-run');
app.commandLine.appendSwitch('no-default-browser-check');
// Disable component extensions (Chrome's built-in internal extensions like PDF
// viewer) — Electron loads different ones which can be detected via chrome.runtime.
app.commandLine.appendSwitch('disable-component-extensions-with-background-pages');
// Ensure the user-data-dir doesn't leak an Electron-specific path in error reports
app.commandLine.appendSwitch('disable-crash-reporter');

// ── YouTube stealth ad-skip content script ────────────────────────────────────
// This is used as an Add-On (ext key: 'yt-ad') — NOT injected automatically.
// Design:
//  • Random variable key per-injection — can't be fingerprinted by name
//  • MutationObserver reacts to player class changes and specific ad nodes only
//  • Polling fallback every 600ms (lightweight, ad-in-progress only)
//  • Saves/restores user mute, volume, playbackRate across each ad
//  • Dismisses skip buttons, overlay ads, and bot-check dialogs
//  • No canvas/pixel readback — avoids GPU stalls and fingerprinting risk
const YT_AD_SKIP = `(function(){
  // Re-entrant guard with cleanup of prior instance
  var _k='_rb'+Math.random().toString(36).slice(2,7);
  if(window._rbYtAdKey){
    try{window[window._rbYtAdKey].obs.disconnect();}catch(e){}
    if(window[window._rbYtAdKey]&&window[window._rbYtAdKey].iv)
      clearInterval(window[window._rbYtAdKey].iv);
    delete window[window._rbYtAdKey];
  }
  window._rbYtAdKey=_k;

  // ── CSS: hide every known non-video ad surface ─────────────────────────────
  if(!document.getElementById('_rb_ac')){
    var _s=document.createElement('style');
    _s.id='_rb_ac';
    _s.textContent=
      'ytd-promoted-sparkles-text-search-renderer,ytd-promoted-video-renderer,'+
      'ytd-display-ad-renderer,ytd-banner-promo-renderer,#masthead-ad,'+
      'ytd-ad-slot-renderer,ytd-in-feed-ad-layout-renderer,'+
      'ytd-action-companion-ad-renderer,ytd-companion-slot-renderer,'+
      'ytd-statement-banner-renderer,.ytd-merch-shelf-renderer,'+
      '#player-ads>.ytd-watch-flexy,#frosted-glass-container,'+
      '.ytp-ad-overlay-container,.ytp-ce-covering-ad,'+
      '.ytp-ce-element,.ytp-ce-covering-overlay,'+
      '.ytp-suggested-action,.ytp-ad-module,'+
      '[id^="google_ads_iframe"],[id^="aswift_"],'+
      '.ad-showing .ytp-pause-overlay,'+
      '.ad-interrupting .ytp-pause-overlay,'+
      '.ytp-ad-text,.ytp-ad-preview-container,.ytp-ad-badge-container,'+
      '.ytp-ad-message-container,.ytp-ad-image-overlay,.ytp-ad-overlay-ad-info-button-container,'+
      'ytd-player-legacy-desktop-watch-ads-renderer,'+
      '.ytp-ad-persistent-progress-bar-container,'+
      '.ytp-ad-progress-list,.ytp-ad-simple-ad-badge,'+
      'ytd-display-ad-renderer[slot],ytd-action-companion-ad-renderer[slot],'+
      '.ytd-video-masthead-ad-v3-renderer,#video-masthead-ad,'+
      'ytd-companion-slot-renderer[slot],'+
      'ytd-rich-item-renderer:has(.ytd-ad-slot-renderer),'+
      'ytd-rich-section-renderer:has(ytd-statement-banner-renderer)'+
      '{display:none!important}';
    (document.head||document.documentElement).appendChild(_s);
  }

  var _wasInAd=false;
  var _userMuted=false,_userRate=1,_userVolume=1;
  var _restoreTimer=null;

  function _inAd(player){
    if(player&&(player.classList.contains('ad-showing')||
                player.classList.contains('ad-interrupting')))return true;
    if(document.querySelector('.ytp-ad-player-overlay-instream-info'))return true;
    if(document.querySelector('.ytp-ad-persistent-progress-bar-container'))return true;
    var adText=document.querySelector('.ytp-ad-text,.ytp-ad-simple-ad-badge');
    if(adText&&adText.offsetParent!==null)return true;
    var skipBtn=document.querySelector('.ytp-ad-skip-button,.ytp-ad-skip-button-modern,.ytp-skip-ad-button,.ytp-ad-skip-button-slot');
    if(skipBtn&&skipBtn.offsetParent!==null)return true;
    var progList=document.querySelector('.ytp-ad-progress-list');
    if(progList&&progList.offsetParent!==null)return true;
    return false;
  }

  function _getVideo(){
    return document.querySelector('#movie_player video.html5-main-video')||
           document.querySelector('#movie_player video')||
           document.querySelector('video');
  }

  function _act(){
    try{
      // 1. Click any visible skip button — cleanest outcome
      var skipBtns=document.querySelectorAll(
        '.ytp-ad-skip-button-modern,.ytp-skip-ad-button,'+
        '.ytp-ad-skip-button,.ytp-ad-skip-button-slot .ytp-button,'+
        'button.ytp-ad-skip-button-modern,'+
        '.ytp-ad-skip-button-container button'
      );
      for(var si=0;si<skipBtns.length;si++){
        var skip=skipBtns[si];
        if(skip&&skip.offsetParent!==null&&!skip.hidden&&skip.offsetWidth>0){
          skip.click();
          setTimeout(_act,350);
          return;
        }
      }

      var player=document.querySelector('#movie_player,.html5-video-player');
      var video=_getVideo();
      var inAd=_inAd(player);

      if(inAd&&video&&video.readyState>0){
        if(!_wasInAd){
          // Save user state on first ad frame only; ignore if already at ad speed
          _userMuted=video.muted;
          _userRate=(video.playbackRate>2)?1:video.playbackRate;
          _userVolume=video.volume;
        }
        _wasInAd=true;
        if(!video.muted)video.muted=true;
        if(video.playbackRate<8)try{video.playbackRate=16;}catch(e){}
        if(video.duration&&isFinite(video.duration)&&video.duration>0.5){
          try{video.currentTime=Math.max(0,video.duration-0.15);}catch(e){}
        }
        if(video.paused&&video.readyState>0)try{video.play();}catch(e){}
      } else if(_wasInAd&&!inAd){
        _wasInAd=false;
        if(_restoreTimer)clearTimeout(_restoreTimer);
        _restoreTimer=setTimeout(function(){
          var v=_getVideo();
          if(v){
            try{v.playbackRate=_userRate||1;}catch(e){}
            try{v.muted=_userMuted;}catch(e){}
            try{v.volume=_userVolume;}catch(e){}
            if(v.paused&&v.readyState>0)try{v.play();}catch(e){}
          }
          _restoreTimer=null;
        },350);
      }

      // 2. Dismiss overlay close buttons
      document.querySelectorAll(
        '.ytp-ad-overlay-close-button,.ytp-ad-overlay-slot-close-button,'+
        '.ytp-suggested-action-badge-expanded-close-button,'+
        '.ytp-ad-overlay-close-container'
      ).forEach(function(el){try{el.click();}catch(e){}});

      // 3. Dismiss bot-check / ad-block enforcement dialogs
      var botDlg=document.querySelector(
        'ytd-enforcement-message-view-model,'+
        'tp-yt-paper-dialog[id*="confirm"],'+
        'ytd-watch-modal tp-yt-paper-dialog,'+
        'ytd-modal-with-title-and-button-renderer'
      );
      if(botDlg&&botDlg.offsetParent!==null){
        var watchBtn=botDlg.querySelector(
          'button[aria-label*="without" i],button[aria-label*="Continue" i],'+
          'button[aria-label*="Watch" i],button[aria-label*="Dismiss" i],'+
          '.yt-spec-button-shape-next--filled,.yt-spec-button-shape-next--tonal'
        );
        if(!watchBtn){
          var btns=botDlg.querySelectorAll('button,.yt-spec-button-shape-next');
          if(btns.length)watchBtn=btns[btns.length-1];
        }
        if(watchBtn){try{watchBtn.click();}catch(e){}}
      }
    }catch(e){}
  }

  // ── MutationObserver — only fires on ad-relevant class/node changes ─────────
  // Observes player attribute changes + ad node additions only (no subtree sieve).
  var _obs=new MutationObserver(function(muts){
    var needAct=false;
    for(var i=0;i<muts.length;i++){
      var t=muts[i].target;
      // Attribute change on player (ad-showing / ad-interrupting class)
      if(muts[i].type==='attributes'&&t&&t.classList&&(
        t.classList.contains('ad-showing')||
        t.classList.contains('ad-interrupting')
      )){needAct=true;break;}
      // Node additions — only care if a known ad node was inserted
      var added=muts[i].addedNodes;
      for(var j=0;j<added.length;j++){
        var n=added[j];
        if(n.nodeType!==1)continue;
        var c=n.className||'';
        if(c.indexOf('ytp-ad')!==-1||c.indexOf('ad-showing')!==-1||c.indexOf('ad-interrupting')!==-1){
          needAct=true;break;
        }
      }
      if(needAct)break;
    }
    if(needAct)_act();
  });

  // ── Polling fallback — only active while an ad is in progress ──────────────
  var _iv=setInterval(function(){
    var p=document.querySelector('#movie_player,.html5-video-player');
    if(_inAd(p)||_wasInAd)_act();
  },600);

  window[_k]={obs:_obs,iv:_iv};

  function _attach(){
    var p=document.querySelector('#movie_player,.html5-video-player,ytd-player');
    if(p){
      _obs.observe(p,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
    } else {
      // Player hasn't rendered yet — wait for it
      var _w=new MutationObserver(function(){
        var p2=document.querySelector('#movie_player,.html5-video-player,ytd-player');
        if(p2){
          _w.disconnect();
          _obs.observe(p2,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
        }
      });
      _w.observe(document.body||document.documentElement,{childList:true,subtree:false});
    }
  }

  _attach();
  _act();
  // Catch late-loading player and in-roll ads on navigation
  setTimeout(_act,400);
  setTimeout(_act,1500);
  setTimeout(_act,3500);
})();`;

// ── YouTube ad-tracking URLs to block at network level ────────────────────────
// Only ad analytics/impression/delivery endpoints — video content is never blocked.
const YT_AD_BLOCK_PATTERNS = [
  /youtube\.com\/api\/stats\/ads/i,
  /youtube\.com\/pagead\//i,
  /youtube\.com\/ptracking/i,
  /googlevideo\.com\/api\/stats\/ads/i,
  /googleads\.g\.doubleclick\.net/i,
  /pubads\.g\.doubleclick\.net/i,      // publisher ad delivery
  /securepubads\.g\.doubleclick\.net/i,
  /static\.doubleclick\.net/i,
  /ad\.doubleclick\.net/i,
  /s0\.2mdn\.net/i,
  // NOTE: imasdk.googleapis.com intentionally NOT blocked — blocking it causes
  // YouTube's player to hang on a black screen because the ad framework can't
  // initialize, which prevents content playback entirely.
  /googleadservices\.com/i,
  /googlesyndication\.com/i,
  /youtube\.com\/pagead\/paralleladview/i,
  /youtube\.com\/api\/stats\/qoe\?.*adformat/i, // QoE only when ad-related
  // 2024/2025 ad logging and survey endpoints
  /jnn-pa\.googleapis\.com\/v1:logAdEvent/i,
  /youtube\.com\/api\/stats\/watchtime\?.*ad/i,
  /youtube\.com\/pagead\/adview/i,
  /youtube\.com\/pagead\/viewthroughconversion/i,
];

// ── Google / auth UA fix ────────────────────────────────────────────────────
// Injected via executeJavaScript (runs in the page's MAIN world, NOT preload
// isolated world, and ignores CSP entirely). This overrides navigator.userAgentData
// so Google's sign-in never sees the real "Electron" brand, which triggers the
// "This browser may not be secure" error at the password step.
// Must run on EVERY navigation to google.com / accounts.google.com etc.
//
// KEY ANTI-DETECTION: Google's scripts use Function.prototype.toString() and
// Object.getOwnPropertyDescriptor() to detect if properties have been overridden
// with custom getters. We wrap both so our overrides appear native.
const GOOGLE_UA_FIX = `(function(){
  if(window._rbGoogleFix)return;
  window._rbGoogleFix=true;
  try{
    /* ── Step 0: Function.prototype.toString stealth ────────────────────────
       Google checks if getters are native by calling fn.toString() and looking
       for "[native code]". We wrap toString so all our custom getters report
       as native. This MUST happen before any _def calls. */
    var _fakeNatives=new WeakSet();
    var _origFnToStr=Function.prototype.toString;
    var _toStrProxy=function toString(){
      if(_fakeNatives.has(this))return'function '+((this.name||'')||'')+'() { [native code] }';
      return _origFnToStr.call(this);
    };
    _fakeNatives.add(_toStrProxy);
    Function.prototype.toString=_toStrProxy;
    /* Also protect Function.prototype.call/apply/bind.toString from revealing overrides */
    try{Object.defineProperty(Function.prototype,'toString',{writable:true,configurable:true});}catch(e){}

    /* ── Step 0b: Object.getOwnPropertyDescriptor stealth ──────────────────
       Google also uses Object.getOwnPropertyDescriptor(navigator, prop) to
       inspect property descriptors and detect custom getters. We intercept
       queries for key navigator properties and return native-looking descriptors. */
    var _origGOPD=Object.getOwnPropertyDescriptor;
    var _spoofedProps=new Map(); /* target -> Set of prop names */
    Object.getOwnPropertyDescriptor=function(obj,prop){
      var s=_spoofedProps.get(obj);
      if(s&&s.has(prop)){
        /* Return descriptor on Navigator.prototype instead — looks like the native one */
        var d=_origGOPD.call(Object,Object.getPrototypeOf(obj)||obj,prop);
        if(d)return d;
      }
      return _origGOPD.call(Object,obj,prop);
    };
    _fakeNatives.add(Object.getOwnPropertyDescriptor);

    var _UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    var _br=[{brand:'Not_A Brand',version:'8'},{brand:'Chromium',version:'120'},{brand:'Google Chrome',version:'120'}];
    var _fvl=[{brand:'Not_A Brand',version:'8.0.0.0'},{brand:'Chromium',version:'120.0.6099.234'},{brand:'Google Chrome',version:'120.0.6099.234'}];
    var _aud={
      brands:_br, mobile:false, platform:'Windows',
      getHighEntropyValues:function getHighEntropyValues(hints){
        return Promise.resolve({architecture:'x86',bitness:'64',brands:_br,
          fullVersionList:_fvl,mobile:false,model:'',
          platform:'Windows',platformVersion:'10.0.0',uaFullVersion:'120.0.6099.234',
          wow64:false});
      },
      toJSON:function toJSON(){return {brands:_br,mobile:false,platform:'Windows'};}
    };
    _fakeNatives.add(_aud.getHighEntropyValues);
    _fakeNatives.add(_aud.toJSON);

    function _def(t,p,v){
      try{
        var g=function(){return v;};
        _fakeNatives.add(g);
        Object.defineProperty(t,p,{get:g,configurable:true});
        /* Track overridden props so GOPD can spoof them */
        if(!_spoofedProps.has(t))_spoofedProps.set(t,new Set());
        _spoofedProps.get(t).add(p);
      }catch(e){}
    }
    _def(navigator,'userAgentData',_aud);
    _def(navigator,'webdriver',false);
    _def(navigator,'userAgent',_UA);
    _def(navigator,'appVersion','5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    _def(navigator,'vendor','Google Inc.');
    _def(navigator,'platform','Win32');
    _def(navigator,'language','en-US');
    _def(navigator,'languages',Object.freeze(['en-US','en']));
    _def(navigator,'hardwareConcurrency',8);
    _def(navigator,'pdfViewerEnabled',true);
    _def(navigator,'cookieEnabled',true);
    _def(navigator,'onLine',true);
    _def(navigator,'maxTouchPoints',0);
    _def(navigator,'appCodeName','Mozilla');
    _def(navigator,'appName','Netscape');
    _def(navigator,'product','Gecko');
    _def(navigator,'productSub','20030107');
    /* Plugins — Chrome always has PDF viewers; empty plugins is a strong signal */
    try{
      var _fp={name:'PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp2={name:'Chrome PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp3={name:'Chromium PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp4={name:'Microsoft Edge PDF Viewer',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fp5={name:'WebKit built-in PDF',description:'Portable Document Format',filename:'internal-pdf-viewer',length:0};
      var _fpl=Object.assign([_fp,_fp2,_fp3,_fp4,_fp5],{namedItem:function(n){return n.includes('PDF')?_fp:null;},item:function(i){return[_fp,_fp2,_fp3,_fp4,_fp5][i]||null;},refresh:function(){}});
      _def(navigator,'plugins',_fpl);
      var _mt=Object.assign([{type:'application/pdf',description:'PDF',enabledPlugin:_fp,suffixes:'pdf'}],{namedItem:function(t){return t==='application/pdf'?{}:null;},item:function(i){return i===0?{}:null;}});
      _def(navigator,'mimeTypes',_mt);
    }catch(e){}
    /* ── window.chrome — delete entirely and rebuild from scratch ───────────
       Electron sets its own chrome.runtime with Electron-specific properties
       (e.g. chrome.runtime.id pointing to internal extension). Assigning over
       it may silently fail if properties are non-configurable. Deleting the
       entire object and recreating it guarantees a clean Chrome-matching shape. */
    try{delete window.chrome;}catch(e){} try{window.chrome=undefined;}catch(e){}
    window.chrome={};
    window.chrome.app={isInstalled:false,InstallState:{DISABLED:'disabled',INSTALLED:'installed',NOT_INSTALLED:'not_installed'},RunningState:{CANNOT_RUN:'cannot_run',READY_TO_RUN:'ready_to_run',RUNNING:'running'},getDetails:function getDetails(){return null;},getIsInstalled:function getIsInstalled(){return false;},installState:function installState(cb){if(cb)cb('not_installed');},runningState:function runningState(){return'cannot_run';}};
    window.chrome.runtime={id:undefined,connect:function connect(){return{postMessage:function(){},onMessage:{addListener:function(){}},disconnect:function(){}};},sendMessage:function sendMessage(){},onMessage:{addListener:function(){}},onConnect:{addListener:function(){}},getPlatformInfo:function getPlatformInfo(cb){if(cb)cb({os:'win',arch:'x86-64',nacl_arch:'x86-64'});return Promise.resolve({os:'win',arch:'x86-64',nacl_arch:'x86-64'});},getManifest:function getManifest(){return undefined;},getURL:function getURL(){return'';},reload:function reload(){},requestUpdateCheck:function requestUpdateCheck(cb){if(cb)cb('no_update',{});}};
    window.chrome.csi=function csi(){return{startE:Date.now(),onloadT:Date.now(),pageT:1000,tran:15};};
    window.chrome.loadTimes=function loadTimes(){return{requestTime:Date.now()/1000,startLoadTime:Date.now()/1000,commitLoadTime:Date.now()/1000,finishDocumentLoadTime:Date.now()/1000,finishLoadTime:Date.now()/1000,firstPaintTime:Date.now()/1000,firstPaintAfterLoadTime:0,navigationType:'Other',wasFetchedViaSpdy:true,wasNpnNegotiated:true,npnNegotiatedProtocol:'h2',wasAlternateProtocolAvailable:false,connectionInfo:'h2'};};
    /* Mark chrome.app/runtime/csi/loadTimes as fake-native for toString checks */
    _fakeNatives.add(window.chrome.app.getDetails);_fakeNatives.add(window.chrome.app.getIsInstalled);
    _fakeNatives.add(window.chrome.app.installState);_fakeNatives.add(window.chrome.app.runningState);
    _fakeNatives.add(window.chrome.runtime.connect);_fakeNatives.add(window.chrome.runtime.sendMessage);
    _fakeNatives.add(window.chrome.runtime.getPlatformInfo);_fakeNatives.add(window.chrome.runtime.getManifest);
    _fakeNatives.add(window.chrome.runtime.getURL);_fakeNatives.add(window.chrome.runtime.reload);
    _fakeNatives.add(window.chrome.runtime.requestUpdateCheck);
    _fakeNatives.add(window.chrome.csi);_fakeNatives.add(window.chrome.loadTimes);
    /* Block WebAuthn/Passkeys — Google falls back to password entry.
       Keep PublicKeyCredential as a constructor but report no platform authenticator
       (setting to undefined is detectable since Chrome always has it). */
    try{
      var _oc=navigator.credentials;
      var _cg=function get(o){if(o&&o.publicKey)return Promise.reject(new DOMException('Not allowed','NotAllowedError'));return _oc?_oc.get.call(_oc,o):Promise.reject(new DOMException('Not allowed','NotAllowedError'));};
      var _cc=function create(o){if(o&&o.publicKey)return Promise.reject(new DOMException('Not allowed','NotAllowedError'));return _oc?_oc.create.call(_oc,o):Promise.reject(new DOMException('Not allowed','NotAllowedError'));};
      _fakeNatives.add(_cg);_fakeNatives.add(_cc);
      Object.defineProperty(navigator,'credentials',{get:function(){return{get:_cg,create:_cc,preventSilentAccess:function(){return Promise.resolve();},store:function(c){return _oc?_oc.store.call(_oc,c):Promise.resolve();}};},configurable:true});
    }catch(e){}
    try{
      if(typeof PublicKeyCredential!=='undefined'){
        var _pkc=function PublicKeyCredential(){throw new TypeError("Illegal constructor");};
        _pkc.isUserVerifyingPlatformAuthenticatorAvailable=function(){return Promise.resolve(false);};
        _pkc.isConditionalMediationAvailable=function(){return Promise.resolve(false);};
        _fakeNatives.add(_pkc);_fakeNatives.add(_pkc.isUserVerifyingPlatformAuthenticatorAvailable);_fakeNatives.add(_pkc.isConditionalMediationAvailable);
        Object.defineProperty(window,'PublicKeyCredential',{value:_pkc,configurable:true,writable:true});
      }
    }catch(e){}
    /* Headless detection: outerWidth/outerHeight === 0 in headless mode */
    try{
      var _ow=window.outerWidth||window.innerWidth||1280;
      var _oh=window.outerHeight||window.innerHeight||720;
      _def(window,'outerWidth',_ow);
      _def(window,'outerHeight',_oh);
    }catch(e){}
    try{
      _def(screen,'availWidth',screen.width||1920);
      _def(screen,'availHeight',screen.height||1080);
      _def(screen,'availLeft',0);
      _def(screen,'availTop',0);
    }catch(e){}
    /* Remove Electron-specific globals */
    try{delete window.Electron;}catch(e){}
    try{delete window.__electron;}catch(e){}
    try{delete window.__electronBinding;}catch(e){}
    try{if(window.process)delete window.process;}catch(e){}
    try{if(window.require)delete window.require;}catch(e){}
    try{if(window.module)delete window.module;}catch(e){}
    try{delete window.Buffer;}catch(e){}
    try{delete window.global;}catch(e){}
    try{delete window.__dirname;}catch(e){}
    try{delete window.__filename;}catch(e){}
    /* Remove non-Chrome browser identity signals */
    try{delete window.opr;}catch(e){}
    try{delete window.opera;}catch(e){}
    try{if(navigator.brave)_def(navigator,'brave',undefined);}catch(e){}
    try{if('globalPrivacyControl' in navigator)_def(navigator,'globalPrivacyControl',false);}catch(e){}
    /* Remove automation/testing globals */
    try{delete window.__nightmare;}catch(e){}
    try{delete window.callPhantom;}catch(e){}
    try{delete window._phantom;}catch(e){}
    try{delete window.domAutomation;}catch(e){}
    try{delete window.domAutomationController;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;}catch(e){}
    try{delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;}catch(e){}
    /* Remove Firefox/legacy signals */
    try{delete window.controllers;}catch(e){}
    try{delete window.Components;}catch(e){}
    try{delete window.mozInnerScreenX;}catch(e){}
    /* clientInformation alias */
    try{if(!window.clientInformation)_def(window,'clientInformation',navigator);}catch(e){}
    /* document.hasFocus() */
    try{var _hf=function hasFocus(){return true;};_fakeNatives.add(_hf);Object.defineProperty(document,'hasFocus',{value:_hf,configurable:true,writable:true});}catch(e){}
    /* navigator.connection */
    try{if(!navigator.connection)_def(navigator,'connection',{effectiveType:'4g',rtt:50,downlink:10,saveData:false,addEventListener:function(){},removeEventListener:function(){}});}catch(e){}
    /* speechSynthesis voices */
    try{if(window.speechSynthesis){var _origGV=window.speechSynthesis.getVoices.bind(window.speechSynthesis);var _fv=[{voiceURI:'Google US English',name:'Google US English',lang:'en-US',localService:true,default:true},{voiceURI:'Google UK English Female',name:'Google UK English Female',lang:'en-GB',localService:false,default:false}];var _gvFn=function getVoices(){var r=_origGV();return(r&&r.length)?r:_fv;};_fakeNatives.add(_gvFn);window.speechSynthesis.getVoices=_gvFn;}}catch(e){}
    /* Notification.permission */
    try{if(typeof Notification!=='undefined')Object.defineProperty(Notification,'permission',{get:function(){return'default';},configurable:true});}catch(e){}
    /* Permission API — return 'prompt' for all permission queries (matches fresh Chrome install) */
    try{if(navigator.permissions){var _origQ=navigator.permissions.query.bind(navigator.permissions);var _pqFn=function query(desc){if(desc&&(desc.name==='notifications'||desc.name==='push'))return Promise.resolve({state:'prompt',status:'prompt',onchange:null});return _origQ(desc);};_fakeNatives.add(_pqFn);navigator.permissions.query=_pqFn;}}catch(e){}
    /* Block service worker registration — SW context doesn't get our overrides,
       so Google's SW could report real Electron identity back to the server. */
    try{if(navigator.serviceWorker){var _origReg=navigator.serviceWorker.register.bind(navigator.serviceWorker);var _srFn=function register(){return Promise.reject(new DOMException('Failed to register a ServiceWorker','SecurityError'));};_fakeNatives.add(_srFn);navigator.serviceWorker.register=_srFn;}}catch(e){}
  }catch(e){}
})();
`;
const _GOOGLE_RE = /google\.com|googleapis\.com|gstatic\.com|gmail\.com|youtube\.com/i;
function _injectGoogleUAFix(wc) {
  if (!wc || wc.isDestroyed()) return;
  try {
    const url = wc.getURL();
    if (url && _GOOGLE_RE.test(url)) {
      wc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
    }
  } catch {}
}

// ── Video PiP — injected into every BV page ──────────────────────────────────
// Button appears at the TOP-RIGHT corner of the video element itself.
// Shows on hover (YouTube / any site) and on autoplay without hover (TikTok).
// Real in-page click → requestPictureInPicture works everywhere.
const VIDEO_PIP_INJECT = `(function(){
  if(window._rawPipV3)return;
  window._rawPipV3=true;

  /* ── Floating PiP button — positioned over video top-right ── */
  var btn=document.createElement('button');
  btn.id='_rawPipBtn';
  btn.style.cssText=
    'position:fixed;z-index:2147483647;top:12px;right:12px;'+
    'background:rgba(0,0,0,.72);color:#fff;'+
    'border:none;border-radius:7px;'+
    'padding:6px 12px 6px 9px;font:600 11px/1.2 -apple-system,sans-serif;'+
    'cursor:pointer;display:flex;align-items:center;gap:5px;'+
    'backdrop-filter:blur(10px);white-space:nowrap;'+
    'box-shadow:0 2px 12px rgba(0,0,0,.65);'+
    'opacity:0;pointer-events:none;'+
    'transition:opacity .16s;';
  btn.innerHTML=
    '<svg width="12" height="12" viewBox="0 0 14 14" fill="none" style="flex-shrink:0">'+
    '<rect x="1" y="2" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.3"/>'+
    '<rect x="6.5" y="6" width="5.5" height="4" rx="1" fill="currentColor" opacity=".75"/>'+
    '</svg><span id="_rawPipLbl">Pop Out</span>';
  document.documentElement.appendChild(btn);

  var _pip=false, _activeV=null, _hideTimer=null, _ro=null;

  /* ── Position button at top-right of a video element ── */
  function _pos(v){
    if(!v)return;
    var r=v.getBoundingClientRect();
    var bw=btn.offsetWidth||90;
    btn.style.top=Math.max(8,r.top+8)+'px';
    btn.style.left=Math.max(0,r.right-bw-8)+'px';
    btn.style.right='auto';
    btn.style.bottom='auto';
  }

  function _show(v){
    clearTimeout(_hideTimer);
    if(v)_activeV=v;
    if(_activeV)_pos(_activeV);
    btn.style.opacity='1';
    btn.style.pointerEvents='all';
  }
  function _hide(delay){
    clearTimeout(_hideTimer);
    _hideTimer=setTimeout(function(){
      btn.style.opacity='0';
      btn.style.pointerEvents='none';
    },delay||0);
  }

  /* Reposition when user scrolls/resizes (keeps button glued to video) */
  function _repos(){
    if(btn.style.opacity==='1'&&_activeV){ _pos(_activeV); }
  }
  window.addEventListener('scroll',_repos,{passive:true,capture:true});
  window.addEventListener('resize',_repos,{passive:true});

  /* ── Bind hover events directly to a video element ── */
  function _bindVideo(v){
    if(v._rawPipBound)return;
    v._rawPipBound=true;
    v.addEventListener('mouseenter',function(){_show(v);},true);
    v.addEventListener('mouseleave',function(e){
      /* Don't hide if mouse moved onto the button */
      if(!_pip&&e.relatedTarget!==btn)_hide(550);
    },true);
    /* Track video resize/position changes so button stays glued to the video */
    if(typeof ResizeObserver!=='undefined'){
      if(_ro)_ro.disconnect();
      _ro=new ResizeObserver(function(){ if(btn.style.opacity==='1'&&_activeV)_pos(_activeV); });
      _ro.observe(v);
    }
  }
  function _bindAll(){
    document.querySelectorAll('video').forEach(_bindVideo);
  }
  _bindAll();

  /* Watch for videos added dynamically (TikTok / YouTube SPA) */
  var _mo=new MutationObserver(function(muts){
    for(var i=0;i<muts.length;i++){
      if(muts[i].addedNodes&&muts[i].addedNodes.length){ _bindAll(); break; }
    }
  });
  _mo.observe(document.documentElement,{childList:true,subtree:true});

  /* ── Also poll for autoplay videos the hover approach can't catch ── */
  /* (TikTok: video plays full-screen without the user hovering)       */
  function _bestPlaying(){
    var vw=window.innerWidth,vh=window.innerHeight,best=null,score=-1;
    document.querySelectorAll('video').forEach(function(v){
      if(v.paused||v.ended)return;
      if(v.readyState<2&&v.videoWidth<1)return;
      var r=v.getBoundingClientRect();
      if(r.width<60||r.height<40)return;
      if(r.right<=0||r.bottom<=0||r.left>=vw||r.top>=vh)return;
      var s=(v.duration||0)*6+(r.width*r.height/6000);
      if(s>score){score=s;best=v;}
    });
    return best;
  }
  function _poll(){
    if(_pip){_show();return;}
    var v=_bestPlaying();
    if(v){ _bindVideo(v); _show(v); }
    /* Don't auto-hide — let mouseleave / _hide handle it */
  }

  /* ── Video play/pause events ── */
  document.addEventListener('play',function(e){
    if(e.target&&e.target.tagName==='VIDEO'){ _bindVideo(e.target); _poll(); }
  },true);
  document.addEventListener('pause',function(e){
    if(e.target&&e.target.tagName==='VIDEO'&&e.target===_activeV){
      if(!_pip) _hide(800);
    }
  },true);

  /* ── PiP state tracking ── */
  document.addEventListener('enterpictureinpicture',function(){
    _pip=true;
    var lbl=document.getElementById('_rawPipLbl');
    if(lbl)lbl.textContent='Exit PiP';
    _show();
  });
  document.addEventListener('leavepictureinpicture',function(){
    _pip=false;
    var lbl=document.getElementById('_rawPipLbl');
    if(lbl)lbl.textContent='Pop Out';
    _hide(700);
  });

  /* Keep button visible when mouse is on it */
  btn.addEventListener('mouseenter',function(){ clearTimeout(_hideTimer); });
  btn.addEventListener('mouseleave',function(e){
    if(!_pip&&e.relatedTarget!==_activeV) _hide(300);
  });

  /* ── Click: enter or exit PiP ── */
  btn.addEventListener('click',function(e){
    e.stopPropagation(); e.preventDefault();
    if(document.pictureInPictureElement){
      document.exitPictureInPicture().catch(function(){});
    }else{
      var v=_activeV||_bestPlaying()||
            document.querySelector('#movie_player video')||
            document.querySelector('.html5-video-player video')||
            document.querySelector('video');
      if(!v)return;
      try{v.disablePictureInPicture=false;}catch(x){}
      v.requestPictureInPicture().catch(function(err){
        console.warn('[RAW PiP]',err.message);
      });
    }
  });

  /* ── Initial poll + recurring poll for autoplay sites ── */
  var _polled=0;
  var _fastIv=setInterval(function(){
    _poll(); _polled++;
    if(_polled>=60){ clearInterval(_fastIv); setInterval(_poll,4000); }
  },1000);
  _poll();
})();`;

// ── Extension content scripts (injected into BrowserView via executeJavaScript) ─
const EXT_SCRIPTS = {
  'dark-mode':
    `(function(){
      if(document.getElementById('_rawDark'))return;
      /* Step 1: Set color-scheme so native inputs render dark */
      var s=document.createElement('style');s.id='_rawDark';
      s.textContent=':root{color-scheme:dark!important;}'+
        '::selection{background:rgba(0,180,160,.5)!important;}';
      document.head.appendChild(s);

      /* Step 2: Smart invert — only on light pages.
         Checks actual computed background of html/body (falls back through
         transparency chain), respects declared color-scheme:dark, and
         skips sites that already have a dark-mode class on <html>/<body>.
         SVG inline elements are re-inverted so icons stay natural. */
      function _applyInvert(){
        if(document.getElementById('_rawDarkInv'))return;
        /* Check if site natively declared dark color-scheme */
        try {
          var cs = getComputedStyle(document.documentElement).colorScheme || '';
          if(cs.includes('dark')) return;
        } catch(e){}
        /* Check for common dark-mode class names on root/body */
        var rootCls = (document.documentElement.className||'')+' '+((document.body||{}).className||'');
        if(/\b(dark|dark-mode|dark-theme|dark-layout|night|black-theme)\b/i.test(rootCls)) return;
        /* Find real background — walk up from body through transparent layers */
        var el=document.body||document.documentElement;
        var bg=getComputedStyle(el).backgroundColor;
        if(bg==='rgba(0, 0, 0, 0)'||bg==='transparent'){
          bg=getComputedStyle(document.documentElement).backgroundColor;
        }
        var m=bg.match(/\\d+/g);
        /* If still transparent or unreadable, assume light (invert) */
        var lum=m&&m.length>=3?(+m[0]*299+(+m[1])*587+(+m[2])*114)/1000:210;
        if(lum<90) return; /* page is already dark — skip */
        var si=document.createElement('style');si.id='_rawDarkInv';
        /* Apply filter to body. SVG added to re-invert list so inline icons
           stay natural. iframe excluded — compositor layer conflict in Electron. */
        si.textContent='body{filter:invert(1) hue-rotate(180deg)!important;}'+
          'img,video,canvas,picture,embed,object,svg,'+
          '[style*="background-image"],[style*="background:url"],[style*="background: url"]'+
          '{filter:invert(1) hue-rotate(180deg)!important}';
        document.head.appendChild(si);
      }
      if(document.readyState==='complete'){_applyInvert();}
      else{window.addEventListener('load',function(){setTimeout(_applyInvert,600);});}
      /* Also run after a 900ms delay so JS-powered dark themes have time to apply */
      setTimeout(_applyInvert,900);
    })()`,
  'no-animations':
    `(function(){if(document.getElementById('_rawNoAnim'))return;var s=document.createElement('style');s.id='_rawNoAnim';s.textContent='*,*::before,*::after{animation:none!important;transition:none!important;}';document.head.appendChild(s);})()`,
  'video-speed':
    `(function(){if(window._rawSpeedUI)return;var el=document.createElement('div');el.id='_rawSpeed';el.style.cssText='position:fixed;bottom:20px;right:20px;z-index:2147483647;background:rgba(0,0,0,.85);color:#00d4c8;font:bold 13px/1 -apple-system,sans-serif;padding:7px 14px;border-radius:8px;cursor:pointer;user-select:none;border:1px solid rgba(0,212,200,.4);';var spd=1;function upd(){el.textContent='\u23e9 '+spd.toFixed(2)+'\u00d7';document.querySelectorAll('video').forEach(function(v){v.playbackRate=spd;});}el.onclick=function(e){e.stopPropagation();spd=spd>=3?0.25:+(spd+0.25).toFixed(2);upd();};document.body.appendChild(el);window._rawSpeedUI=el;upd();})()`,
  'focus-mode':
    `(function(){if(document.getElementById('_rawFocus'))return;var s=document.createElement('style');s.id='_rawFocus';s.textContent='header,nav,footer,aside,[class*="sidebar"],[class*="widget"],[class*="banner"],[class*="promo"],[class*="recommend"],[class*="related"],[id*="sidebar"],[id*="nav"]{opacity:.08!important;pointer-events:none!important;}main,article,[role="main"],[class*="article-body"],[class*="post-content"],[class*="entry-content"]{max-width:700px!important;margin:0 auto!important;padding:0 24px!important;}';document.head.appendChild(s);})()`,
  'grayscale':
    `(function(){if(document.getElementById('_rawGray'))return;var s=document.createElement('style');s.id='_rawGray';s.textContent='html{filter:grayscale(1)!important;}';document.head.appendChild(s);})()`,
  'night-filter':
    `(function(){if(document.getElementById('_rawNight'))return;var d=document.createElement('div');d.id='_rawNight';d.style.cssText='position:fixed;inset:0;background:rgba(255,130,0,.18);pointer-events:none;z-index:2147483646;';document.documentElement.appendChild(d);})()`,
  'highlight-links':
    `(function(){if(document.getElementById('_rawLinks'))return;var s=document.createElement('style');s.id='_rawLinks';s.textContent='a{text-decoration-line:underline!important;text-decoration-color:rgba(0,212,200,.55)!important;text-underline-offset:2px!important;}';document.head.appendChild(s);})()`,
  'scroll-progress':
    `(function(){if(document.getElementById('_rawScProg'))return;var b=document.createElement('div');b.id='_rawScProg';b.style.cssText='position:fixed;top:0;left:0;height:3px;width:0%;background:linear-gradient(90deg,#00d4c8,#00bdb0);z-index:2147483646;transition:width .08s linear;pointer-events:none';document.documentElement.appendChild(b);function _upd(){var s=document.documentElement;var p=s.scrollTop/(s.scrollHeight-s.clientHeight)*100;b.style.width=Math.min(100,isNaN(p)?0:p)+'%';}window.addEventListener('scroll',_upd,{passive:true});})()`,
  'font-boost':
    `(function(){if(document.getElementById('_rawFont'))return;var s=document.createElement('style');s.id='_rawFont';s.textContent='body,p,li,td,th,article,section,main{font-size:108%!important;line-height:1.75!important;}';document.head.appendChild(s);})()`,
  'reader-mode':
    `(function(){if(document.getElementById('_rawReader'))return;var s=document.createElement('style');s.id='_rawReader';s.textContent='body,article,main,section{max-width:740px!important;margin:0 auto!important;padding:32px 28px!important;font-size:18px!important;line-height:1.9!important;background:#111!important;color:#d8d8d8!important;font-family:Georgia,serif!important;}h1,h2,h3,h4,h5,h6{color:#f0f0f0!important;line-height:1.3!important;margin:1.4em 0 .5em!important;}a{color:#00d4c8!important;}p,li{color:#d0d0d0!important;}img,video,picture,figure,iframe,canvas,svg[width][height],embed,object,.image,[class*="image"],[class*="photo"],[class*="media"],[class*="gallery"][class*="caption"]{display:none!important;}nav,header,footer,aside,[role="banner"],[role="navigation"],[role="complementary"],[class*="sidebar"],[id*="sidebar"],[class*="nav"],[id*="nav"],[class*="header"],[id*="header"],[class*="footer"],[id*="footer"],[class*="related"],[class*="recommend"],[class*="ad-"],[id*="-ad"],[class*="ad_"],[class*="advert"],[class*="banner"],[class*="popup"],[class*="modal"],[class*="cookie"],[class*="toolbar"],[class*="social"],[class*="share"]{display:none!important;}';document.head.appendChild(s);})()`,
  'image-zoom':
    `(function(){if(window._rawImgZoom)return;window._rawImgZoom=true;var ov=document.createElement('div');ov.id='_rawImgZoomOv';ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:2147483647;display:none;align-items:center;justify-content:center;cursor:zoom-out;backdrop-filter:blur(6px)';var im=document.createElement('img');im.style.cssText='max-width:92vw;max-height:92vh;border-radius:6px;box-shadow:0 4px 60px rgba(0,0,0,.9)';ov.appendChild(im);document.documentElement.appendChild(ov);ov.addEventListener('click',function(){ov.style.display='none';});document.addEventListener('click',function(e){if(e.target.tagName==='IMG'&&e.target.naturalWidth>200){im.src=e.target.src;ov.style.display='flex';}});})()`,
  'word-count':
    `(function(){if(document.getElementById('_rawWordCnt'))return;var w=(document.body.innerText||'').trim().split(/\s+/).filter(Boolean).length;var m=Math.max(1,Math.round(w/200));var b=document.createElement('div');b.id='_rawWordCnt';b.style.cssText='position:fixed;bottom:18px;right:18px;background:rgba(10,10,10,.82);color:#aaa;font-size:11.5px;padding:5px 12px;border-radius:20px;z-index:2147483646;pointer-events:none;backdrop-filter:blur(10px);font-family:system-ui,sans-serif;letter-spacing:.02em;border:1px solid rgba(255,255,255,.08)';b.textContent=w.toLocaleString()+' words · '+m+' min read';document.documentElement.appendChild(b);})()`,
  'anti-tracking':
    `(function(){if(document.getElementById('_rawAntiTrk'))return;var s=document.createElement('style');s.id='_rawAntiTrk';s.textContent='img[width="1"],img[height="1"],img[width="0"],img[height="0"],img[style*="display:none"],img[style*="display: none"]{display:none!important;visibility:hidden!important;}';document.head.appendChild(s);})()`,
  'print-clean':
    `(function(){if(document.getElementById('_rawPrint'))return;var s=document.createElement('style');s.id='_rawPrint';s.textContent='@media print{nav,header,footer,aside,iframe,[class*="ad"],[id*="ad"],[class*="banner"],[class*="sidebar"],[class*="popup"],[class*="cookie"],[class*="social"],[class*="share"],[class*="related"]{display:none!important}body{font-size:11pt!important;line-height:1.6!important;color:#000!important;background:#fff!important}a::after{content:" ("attr(href)")";}img{max-width:100%!important}}';document.head.appendChild(s);})()`,
  'smooth-scroll':
    `(function(){if(document.getElementById('_rawSmooth'))return;var s=document.createElement('style');s.id='_rawSmooth';s.textContent='html{scroll-behavior:smooth!important;}';document.head.appendChild(s);})()`,
  'smart-copy':
    `(function(){if(window._rawSmartCopy)return;window._rawSmartCopy=true;document.addEventListener('copy',function(e){var sel=window.getSelection();if(!sel||!sel.toString())return;e.preventDefault();e.clipboardData.setData('text/plain',sel.toString());},true);})()`,
  'hide-comments':
    `(function(){if(document.getElementById('_rawHideCom'))return;var s=document.createElement('style');s.id='_rawHideCom';s.textContent='[id*="comment" i],[class*="comment" i],[id*="disqus"],[class*="disqus"],[id*="discuss" i],[class*="discuss" i],[id*="replies" i],[class*="replies" i]{display:none!important;}';document.head.appendChild(s);})()`,
  'link-preview':
    `(function(){if(window._rawLinkPrev)return;window._rawLinkPrev=true;var tip=document.createElement('div');tip.id='_rawLinkPrev';tip.style.cssText='position:fixed;bottom:12px;left:50%;transform:translateX(-50%);max-width:520px;background:rgba(12,12,12,.92);color:#a0a0a0;font:12px/1.4 system-ui,sans-serif;padding:4px 14px;border-radius:7px;z-index:2147483646;pointer-events:none;opacity:0;transition:opacity .15s;backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;';document.documentElement.appendChild(tip);document.addEventListener('mouseover',function(e){var a=e.target.closest('a');if(a&&a.href&&!/^javascript/i.test(a.href)){tip.textContent=a.href;tip.style.opacity='1';}});document.addEventListener('mouseout',function(e){if(e.target.closest('a'))tip.style.opacity='0';});})()`,
  'custom-cursor':
    `(function(){if(window._rawCursor)return;window._rawCursor=true;var tr=document.createElement('div');tr.id='_rawCursorRing';tr.style.cssText='position:fixed;width:22px;height:22px;border-radius:50%;border:1.5px solid rgba(0,212,200,.75);pointer-events:none;z-index:2147483647;transform:translate(-50%,-50%);transition:top .06s linear,left .06s linear;top:-100px;left:-100px;box-shadow:0 0 10px rgba(0,212,200,.35);';document.documentElement.appendChild(tr);document.addEventListener('mousemove',function(e){tr.style.top=e.clientY+'px';tr.style.left=e.clientX+'px';});})()`,
  'auto-scroll':
    `(function(){if(window._rawAutoScrollBtn)return;var spd=0,anim,btn=document.createElement('div');btn.id='_rawAutoScrollBtn';btn.style.cssText='position:fixed;bottom:60px;right:20px;z-index:2147483647;background:rgba(0,0,0,.85);color:#00d4c8;font:bold 12px/1 system-ui;padding:6px 14px;border-radius:8px;cursor:pointer;user-select:none;border:1px solid rgba(0,212,200,.4);';btn.textContent='\u25bc Auto';window._rawAutoScrollBtn=btn;function tick(){if(spd>0){window.scrollBy(0,spd);anim=requestAnimationFrame(tick);}}btn.onclick=function(e){e.stopPropagation();spd=spd>0?0:1.5;btn.textContent=spd>0?'\u25a0 Stop':'\u25bc Auto';if(spd>0)anim=requestAnimationFrame(tick);else if(anim)cancelAnimationFrame(anim);};document.body.appendChild(btn);})()`,
  'high-contrast':
    `(function(){if(document.getElementById('_rawHiCon'))return;var s=document.createElement('style');s.id='_rawHiCon';s.textContent='html{filter:contrast(1.65)!important;}';document.head.appendChild(s);})()`,
  'pip-mode':
    // Trigger PiP via the floating button injected by VIDEO_PIP_INJECT — it has a
    // real user-gesture context from the click event (IPC-direct requestPiP fails).
    `(function(){
      window._rawPip=true;
      // If VIDEO_PIP_INJECT button is already in the page, use it (has user gesture)
      var btn=document.getElementById('_rawPipBtn');
      if(btn){
        var ev=new MouseEvent('click',{bubbles:true,cancelable:true,view:window});
        btn.dispatchEvent(ev);
        return;
      }
      // Fallback: find best visible video and attempt PiP (may need a real user gesture
      // but works on pages that allow autoplay with permissions policy)
      var vw=window.innerWidth,vh=window.innerHeight;
      var best=null,bestScore=-1;
      document.querySelectorAll('video').forEach(function(v){
        var r=v.getBoundingClientRect();
        if(r.width<80||r.height<50)return;
        var score=(v.paused?0:3000)+(v.duration||0)*10+(r.width*r.height/1e4);
        if(score>bestScore){bestScore=score;best=v;}
      });
      if(!best)best=document.querySelector('#movie_player video')||document.querySelector('video');
      if(best){
        try{best.disablePictureInPicture=false;}catch(e){}
        best.requestPictureInPicture().catch(function(err){
          console.warn('[RAW pip-mode]',err.message,'— hover the video and use the Pop Out button');
        });
      }
    })()`,
  'sticky-notes':
    `(function(){if(window._rawStickyNotes)return;window._rawStickyNotes=true;var d=document.createElement('div');d.id='_rawStickyNotes';d.style.cssText='position:fixed;bottom:80px;right:20px;z-index:2147483647;width:230px;background:rgba(10,10,10,.97);border-radius:12px;border:1px solid rgba(0,212,200,.3);box-shadow:0 4px 24px rgba(0,0,0,.6);overflow:hidden;font-family:system-ui,sans-serif;';var hdr=document.createElement('div');hdr.style.cssText='padding:8px 12px;background:rgba(0,212,200,.1);font-size:11px;font-weight:700;color:#00d4c8;cursor:move;display:flex;align-items:center;justify-content:space-between;user-select:none;';hdr.innerHTML='<span>\u{1F4DD} STICKY NOTE</span>';var cls=document.createElement('button');cls.textContent='\u00d7';cls.style.cssText='background:none;border:none;color:#666;font-size:16px;cursor:pointer;padding:0 2px;line-height:1;';cls.onclick=function(){d.remove();window._rawStickyNotes=false;};hdr.appendChild(cls);var ta=document.createElement('textarea');ta.style.cssText='width:100%;height:110px;background:transparent;border:none;border-top:1px solid rgba(255,255,255,.07);padding:10px 12px;color:#ccc;font-size:12px;resize:vertical;outline:none;box-sizing:border-box;font-family:inherit;line-height:1.5;';ta.placeholder='Type notes\u2026';d.appendChild(hdr);d.appendChild(ta);document.documentElement.appendChild(d);var mx=0,my=0,drag=false;hdr.addEventListener('mousedown',function(e){drag=true;mx=e.clientX-d.offsetLeft;my=e.clientY-d.offsetTop;});document.addEventListener('mousemove',function(e){if(!drag)return;d.style.right='auto';d.style.bottom='auto';d.style.left=(e.clientX-mx)+'px';d.style.top=(e.clientY-my)+'px';});document.addEventListener('mouseup',function(){drag=false;});})()`,
  'low-data':
    `(function(){if(document.getElementById('_rawLowData'))return;var s=document.createElement('style');s.id='_rawLowData';s.textContent='img,picture,svg image{visibility:hidden!important;}video,iframe[src*="youtube"],iframe[src*="vimeo"]{display:none!important;}';document.head.appendChild(s);var b=document.createElement('div');b.id='_rawLowDataBadge';b.style.cssText='position:fixed;top:10px;right:10px;z-index:2147483646;background:rgba(10,10,10,.9);color:#f0c030;font:700 10px/1 system-ui;padding:4px 10px;border-radius:6px;border:1px solid rgba(240,192,48,.3);pointer-events:none;letter-spacing:.06em;';b.textContent='LOW DATA MODE';document.documentElement.appendChild(b);})()`,
  'neon-glow':
    `(function(){if(document.getElementById('_rawNeonGlow'))return;var s=document.createElement('style');s.id='_rawNeonGlow';s.textContent='h1,h2,h3{text-shadow:0 0 14px rgba(0,212,200,.55),0 0 32px rgba(0,212,200,.2)!important;color:#e0fffe!important;}a:hover{text-shadow:0 0 8px rgba(0,212,200,.65)!important;color:#00ffec!important;}button,input[type="submit"]{box-shadow:0 0 10px rgba(0,212,200,.35),0 0 22px rgba(0,212,200,.12)!important;}';document.head.appendChild(s);})()`,
  'page-zoom':
    `(function(){if(window._rawZoomCtrl)return;window._rawZoomCtrl=true;var lvl=1;var wrap=document.createElement('div');wrap.id='_rawZoomCtrl';wrap.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:2147483647;display:flex;align-items:center;gap:6px;background:rgba(10,10,10,.92);border:1px solid rgba(0,212,200,.28);border-radius:10px;padding:5px 10px;font-family:system-ui;box-shadow:0 4px 16px rgba(0,0,0,.5);';function _btn(t){var b=document.createElement('button');b.textContent=t;b.style.cssText='background:rgba(0,212,200,.12);border:1px solid rgba(0,212,200,.25);color:#00d4c8;font-size:14px;font-weight:700;width:26px;height:26px;border-radius:6px;cursor:pointer;';return b;}var bM=_btn('-'),lbl=document.createElement('span'),bP=_btn('+'),bR=_btn('\u21ba');lbl.style.cssText='color:#ccc;font-size:11px;font-weight:600;min-width:38px;text-align:center;';lbl.textContent='100%';function _sz(z){lvl=Math.min(3,Math.max(0.3,z));document.body.style.zoom=lvl;lbl.textContent=Math.round(lvl*100)+'%';}bM.onclick=function(){_sz(+(lvl-0.1).toFixed(1));};bP.onclick=function(){_sz(+(lvl+0.1).toFixed(1));};bR.onclick=function(){_sz(1);};[bM,lbl,bP,bR].forEach(function(el){wrap.appendChild(el);});document.documentElement.appendChild(wrap);})()`,
  // YouTube Ad Skipper — enabled as an add-on, not automatically
  'yt-ad': YT_AD_SKIP,
};

const EXT_UNSCRIPTS = {
  'dark-mode':       `(function(){['_rawDark','_rawDarkInv'].forEach(function(id){var e=document.getElementById(id);if(e)e.remove();});})()`,
  'no-animations':   `(function(){var s=document.getElementById('_rawNoAnim');if(s)s.remove();})()`,
  'video-speed':     `(function(){var el=document.getElementById('_rawSpeed');if(el)el.remove();delete window._rawSpeedUI;})()`,
  'focus-mode':      `(function(){var s=document.getElementById('_rawFocus');if(s)s.remove();})()`,
  'grayscale':       `(function(){var s=document.getElementById('_rawGray');if(s)s.remove();})()`,
  'night-filter':    `(function(){var el=document.getElementById('_rawNight');if(el)el.remove();})()`,
  'highlight-links':  `(function(){var s=document.getElementById('_rawLinks');if(s)s.remove();})()`, 
  'scroll-progress':  `(function(){document.getElementById('_rawScProg')?.remove();})()`,
  'font-boost':       `(function(){document.getElementById('_rawFont')?.remove();})()`,
  'reader-mode':      `(function(){document.getElementById('_rawReader')?.remove();})()`,
  'image-zoom':       `(function(){document.getElementById('_rawImgZoomOv')?.remove();window._rawImgZoom=false;})()`,
  'word-count':       `(function(){document.getElementById('_rawWordCnt')?.remove();})()`,
  'anti-tracking':    `(function(){document.getElementById('_rawAntiTrk')?.remove();})()`,
  'print-clean':      `(function(){document.getElementById('_rawPrint')?.remove();})()`,
  'smooth-scroll':    `(function(){document.getElementById('_rawSmooth')?.remove();})()`,
  'smart-copy':       `(function(){window._rawSmartCopy=false;})()`,
  'hide-comments':    `(function(){document.getElementById('_rawHideCom')?.remove();})()`,
  'link-preview':     `(function(){document.getElementById('_rawLinkPrev')?.remove();window._rawLinkPrev=false;})()`,
  'custom-cursor':    `(function(){document.getElementById('_rawCursorRing')?.remove();window._rawCursor=false;})()`,
  'auto-scroll':      `(function(){var b=document.getElementById('_rawAutoScrollBtn');if(b)b.remove();window._rawAutoScrollBtn=false;})()`,
  'high-contrast':    `(function(){document.getElementById('_rawHiCon')?.remove();})()`,
  'pip-mode':         `(function(){if(document.pictureInPictureElement)document.exitPictureInPicture().catch(function(){});window._rawPip=false;})()`,
  'sticky-notes':     `(function(){document.getElementById('_rawStickyNotes')?.remove();window._rawStickyNotes=false;})()`,
  'low-data':         `(function(){document.getElementById('_rawLowData')?.remove();document.getElementById('_rawLowDataBadge')?.remove();})()`,
  'neon-glow':        `(function(){document.getElementById('_rawNeonGlow')?.remove();})()`,
  'page-zoom':        `(function(){document.getElementById('_rawZoomCtrl')?.remove();try{if(document.body)document.body.style.zoom='';}catch(e){}window._rawZoomCtrl=false;})()`,
  'yt-ad':            `(function(){try{if(window._rbYtAdKey){var k=window._rbYtAdKey;window[k]&&window[k].obs&&window[k].obs.disconnect();window[k]&&window[k].iv&&clearInterval(window[k].iv);delete window[k];delete window._rbYtAdKey;}var s=document.getElementById('_rb_ac');if(s)s.remove();}catch(e){}})()`,
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function load(file, fb) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fb; }
}
function save(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data)); } catch(e) {}
}

// ── Default settings ──────────────────────────────────────────────────────────
const DEF_SETTINGS = {
  adblockEnabled: true, blockTelemetry: true, blockCrossSite: true,
  strictPrivacy:  true, spoofUserAgent:  true, doNotTrack:    true,
  hardwareAcceleration: true,
  searchEngine: 'https://duckduckgo.com/?q=',
  homepage: 'newtab', accentColor: 'teal',
  wallpaperColor: '#080808', wallpaper: null,
  showSidebar: false, sidebarSites: [],
  showFavicons: true,
  extensions: {},
  translateLang: 'en',
  geoEnabled: false,
  geoRegion: 'new-york',
  toolbar: { 'tb-geo': false, 'tb-calc': false, 'tb-notes': false },
};

// ── App state (populated in initStorage after app ready) ──────────────────────
let settings      = { ...DEF_SETTINGS };
let bookmarks     = [];
let history       = [];
let downloads     = [];
let userWhitelist = [];
let F             = {};   // file paths, set in initStorage()

// Called inside app.whenReady() — app.getPath() only works after ready
function initStorage() {
  const DATA = path.join(app.getPath('userData'), 'rawbrowser');
  if (!fs.existsSync(DATA)) fs.mkdirSync(DATA, { recursive: true });
  F = {
    settings:  path.join(DATA, 'settings.json'),
    history:   path.join(DATA, 'history.json'),
    bookmarks: path.join(DATA, 'bookmarks.json'),
    downloads: path.join(DATA, 'downloads.json'),
    whitelist: path.join(DATA, 'whitelist.json'),
  };
  settings      = { ...DEF_SETTINGS, ...load(F.settings,  {}) };
  bookmarks     = load(F.bookmarks, []);
  history       = load(F.history,   []);
  downloads     = load(F.downloads, []);
  userWhitelist = load(F.whitelist, []);
}

// ── Runtime ───────────────────────────────────────────────────────────────────
let   CHROME_H   = 82;   // matches --chrome-h; updated dynamically for compact mode (72)
const SIDEBAR_W  = 64;   // sidebar strip width
let   sidebarOn  = false;
let   nextId     = 0;
const tabMap   = new Map();
let   activeId = null;
let   win      = null;
let   totalBlocked = 0;
let   panelOpen    = false;
let   panelClipX   = 0;       // >0 = BV clipped to leave room for open panel
let   _panelSeq         = 0;        // increments on every panel:show:* to cancel stale async chains

// ── IPC shortcut ──────────────────────────────────────────────────────────────
function send(ch, ...a) {
  if (win && !win.isDestroyed()) win.webContents.send(ch, ...a);
}

// ── Tab serialization ─────────────────────────────────────────────────────────
function tabData(t) {
  return {
    id: t.id, url: t.url, title: t.title,
    favicon: t.favicon, loading: t.loading,
    pinned: t.pinned, muted: t.muted,
    isAudible: t.isAudible || false,
  };
}

function _getAudioTabs() {
  return [...tabMap.values()]
    .filter(t => t.isAudible || t.muted)
    .map(t => ({ id: t.id, title: t.title, favicon: t.favicon, isAudible: t.isAudible, muted: t.muted, volume: t.volume ?? 1, paused: t.paused ?? false }));
}

function navData(t) {
  const wc = t?.bv?.webContents;
  return {
    url:          t?.url     || '',
    canBack:      wc ? wc.canGoBack()    : false,
    canFwd:       wc ? wc.canGoForward() : false,
    loading:      t?.loading || false,
    favicon:      t?.favicon || null,
    muted:        t?.muted   || false,
    zoom:         t?.zoom    || 1,
    blocked:      t?.blocked || 0,
    blockedTotal: totalBlocked,
  };
}

// ── BrowserView sizing ────────────────────────────────────────────────────────
function setBounds(bv) {
  if (!win || !bv) return;
  const [w, h] = win.getContentSize();
  const x = sidebarOn ? SIDEBAR_W : 0;
  // If a panel is clipping the BV width (to show panel in uncovered area), respect it
  const bvW = panelClipX > 0 ? Math.max(0, panelClipX - x) : Math.max(0, w - x);
  bv.setBounds({ x, y: CHROME_H, width: bvW, height: Math.max(h - CHROME_H, 0) });
}

// ── Park BV offscreen instead of removing it ────────────────────────────────
// Keeps the GPU compositor alive so video/audio never freezes or pauses.
// The BV is still "attached" to the window but positioned far off-screen left.
// panel:hide calls setBounds() to restore it to the correct position.
function _parkBV(bv) {
  if (!bv || bv.webContents.isDestroyed()) return;
  const [w, h] = win.getContentSize();
  const bvH = Math.max(h - CHROME_H, 1);
  // Keep the same width the BV was rendering at so the page doesn't reflow
  // when parked. Using full `w` when the sidebar is open would make the page
  // re-render wider than it was, causing a layout change visible in the live
  // capture loop (wrong aspect ratio / content shifted).
  const bvW = sidebarOn ? Math.max(w - SIDEBAR_W, 1) : w;
  try { win.addBrowserView(bv); } catch {}
  // incrementCapturerCount(size) puts Chromium into off-screen rendering mode:
  //   1. Prevents the renderer from being suspended (WasHidden() is blocked)
  //   2. Keeps the video decoder producing frames into an off-screen buffer so
  //      capturePage() returns live video frames even with no visible pixels.
  // Pass the exact visible size so the page renders at its original resolution.
  try { bv.webContents.incrementCapturerCount({ width: bvW, height: bvH }); } catch {}
  // Move BV fully off the left edge — zero visible pixels in the window so HTML
  // panels render unobstructed. BV stays attached so the compositor frame sink
  // remains alive and video/audio never pauses.
  bv.setBounds({ x: -(w + 10), y: CHROME_H, width: bvW, height: bvH });
}
function _unparkBV(bv) {
  if (!bv || bv.webContents.isDestroyed()) return;
  try { bv.webContents.decrementCapturerCount(); } catch {}
  try { win.addBrowserView(bv); } catch {}
  try { setBounds(bv); } catch {}
}

// ── URL helpers ───────────────────────────────────────────────────────────────
function normalizeUrl(raw) {
  if (!raw || raw === 'about:blank') return 'newtab';
  if (raw.includes('newtab.html'))   return 'newtab';
  return raw;
}

function resolveUrl(raw) {
  if (!raw || raw === 'newtab') return 'newtab';
  const engine = settings.searchEngine || 'https://duckduckgo.com/?q=';
  // Allow file:// URLs and bare paths pointing to local html/xhtml/pdf files
  if (/\.(html?|xhtml|pdf)$/i.test(raw) && !/^(javascript|vbscript|data):/i.test(raw)) return raw;
  // Security: never navigate to dangerous schemes — treat as search queries
  if (/^(javascript|vbscript|data|file):/i.test(raw)) return engine + encodeURIComponent(raw);
  if (/^(https?|ftp):\/\//i.test(raw))   return raw;
  if (/^(about:|view-source:)/i.test(raw)) return raw;
  if (/^localhost(:\d+)?(\/.*)?$/.test(raw)) return 'http://' + raw;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(raw)) return 'https://' + raw;
  return engine + encodeURIComponent(raw);
}

function stripTracking(url) {
  if (!settings.strictPrivacy) return url;
  try {
    const u = new URL(url);
    ['utm_source','utm_medium','utm_campaign','utm_term','utm_content',
     'fbclid','gclid','msclkid','twclid','dclid','mc_eid','mc_cid','ref'
    ].forEach(p => u.searchParams.delete(p));
    return u.toString();
  } catch { return url; }
}

function addHistory(url, title) {
  if (!url || url === 'newtab' || url.startsWith('about:') || url.startsWith('file://')) return;
  history.unshift({ url, title: title || url, ts: Date.now() });
  if (history.length > 10000) history.length = 10000;
  save(F.history, history);
  send('history:set', history);
}

// ── Tab activation ─────────────────────────────────────────────────────────────
function activateTab(id) {
  const tab = tabMap.get(id);
  if (!tab || !win) return;

  // If a panel was open, close it now — switching tabs must always restore the UI
  if (panelOpen) {
    panelOpen  = false;
    panelClipX = 0;
    // Restore the outgoing tab's BV dimensions in case it was parked at 2×2
    const oldTab = tabMap.get(activeId);
    if (oldTab?.bv && !oldTab.bv.webContents.isDestroyed()) {
      oldTab.bv.webContents.executeJavaScript(PANEL_RESTORE_ALIVE_JS).catch(() => {});
    }
    // Tell the renderer to close any open panel / overlay
    send('panels:closeAll');
  }

  // Remove all BrowserViews first
  for (const t of tabMap.values()) {
    if (t.bv) try { win.removeBrowserView(t.bv); } catch {}
  }
  
  // Only attach BrowserView for real pages — newtab is handled by HTML newtab-layer
  if (tab.bv && tab.url !== 'newtab') {
    win.addBrowserView(tab.bv);
    setBounds(tab.bv);
  }
  
  activeId = id;
  send('tab:activate', id);
  send('nav:state', navData(tab));
  // Always refresh privacy-panel stats when switching tabs
  send('blocked:update', { total: totalBlocked, session: tab.blocked || 0 });
}

// ── Tab creation ───────────────────────────────────────────────────────────────
function createTab(url, activate = true) {
  const id = ++nextId;
  const bv = new BrowserView({
    backgroundColor: '#080808',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      partition:        'persist:main',
      preload:          path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: true,
    },
  });

  const tab = {
    id, bv,
    url: 'newtab', title: 'New Tab', favicon: null,
    loading: false, pinned: false, muted: false, zoom: 1, blocked: 0,
  };
  tabMap.set(id, tab);

  const wc = bv.webContents;
  // Prevent Chromium from throttling/pausing the renderer when it's not
  // composited into the window (e.g. while a toolbar panel is open with BV removed).
  // Without this, video/audio can pause at the media pipeline level regardless of
  // any JS-level visibility overrides.
  wc.setBackgroundThrottling(false);
  wc.setUserAgent(SPOOF_UA);

  // Auth provider domains that use popup-based OAuth flows.
  // Returning { action: 'allow' } lets Electron create a real popup window so the
  // parent page can hold onto the window reference and detect when login completes.
  const _oauthDomains = [
    'accounts.google.com', 'google.com', 'googleusercontent.com',
    'login.microsoftonline.com', 'appleid.apple.com',
    'facebook.com', 'discord.com',
  ];
  wc.setWindowOpenHandler(({ url: u }) => {
    // Block dangerous schemes
    if (/^(javascript|vbscript|file):/i.test(u)) return { action: 'deny' };
    // Allow native popup for OAuth providers so the auth flow can complete.
    // Also allow about:blank popups — many OAuth flows open about:blank first,
    // then navigate to the auth URL from JS.
    const isBlank = !u || u === 'about:blank';
    let isAuth = false;
    if (!isBlank) {
      try {
        const host = new URL(u).hostname;
        isAuth = _oauthDomains.some(d => host === d || host.endsWith('.' + d));
      } catch {}
    }
    if (isAuth || isBlank) {
      return {
        action: 'allow',
        overrideBrowserWindowOptions: {
          width: 500, height: 650,
          autoHideMenuBar: true,
          webPreferences: {
            partition: 'persist:main',
            contextIsolation: true,
            nodeIntegration: false,
            preload: path.join(__dirname, 'preload.js'),
          },
        },
      };
    }
    createTab(u, true);
    return { action: 'deny' };
  });

  // Apply UA spoofing to OAuth popup windows.
  // IMPORTANT: Do NOT add a will-navigate guard here — OAuth flows redirect the
  // popup to the original site's callback URL (e.g. example.com/oauth/callback)
  // to pass the auth code. Intercepting that navigation closes the popup before
  // the parent page can read the result, permanently breaking login.
  wc.on('did-create-window', (popup) => {
    const pwc = popup.webContents;
    pwc.setUserAgent(SPOOF_UA);
    pwc.setBackgroundThrottling(false);
    popup.setMenuBarVisibility(false);
    // Inject Google UA fix at the earliest moment (before page scripts) + on later events.
    pwc.on('did-commit-navigation', (_, navUrl) => {
      if (navUrl && _GOOGLE_RE.test(navUrl)) pwc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
    });
    pwc.on('dom-ready', () => _injectGoogleUAFix(pwc));
    pwc.on('did-navigate', () => _injectGoogleUAFix(pwc));
    pwc.on('did-navigate-in-page', () => _injectGoogleUAFix(pwc));
  });

  // Inject Google UA fix at the EARLIEST possible moment (did-commit-navigation fires
  // before page scripts run — earlier than dom-ready) so Google never sees Electron.
  wc.on('did-commit-navigation', (_, navUrl) => {
    if (navUrl && _GOOGLE_RE.test(navUrl)) wc.executeJavaScript(GOOGLE_UA_FIX).catch(() => {});
  });
  // Belt-and-suspenders: also inject on later events to cover SPA navigations.
  wc.on('dom-ready', () => _injectGoogleUAFix(wc));
  wc.on('did-navigate', () => _injectGoogleUAFix(wc));
  wc.on('did-navigate-in-page', () => _injectGoogleUAFix(wc));

  // ── Right-click context menu ───────────────────────────────────────────────
  wc.on('context-menu', (_, p) => {
    const items = [];

    if (p.linkURL && !/^(javascript|vbscript):/i.test(p.linkURL)) {
      items.push(
        { label: 'Open Link in New Tab',  click: () => createTab(p.linkURL, false) },
        { label: 'Copy Link Address',      click: () => clipboard.writeText(p.linkURL) },
        { type: 'separator' },
      );
    }

    if (p.hasImageContents && p.srcURL) {
      items.push(
        { label: 'Open Image in New Tab', click: () => createTab(p.srcURL, false) },
        { label: 'Copy Image Address',     click: () => clipboard.writeText(p.srcURL) },
        { label: 'Save Image As…',         click: () => wc.downloadURL(p.srcURL) },
        { type: 'separator' },
      );
    }

    if (p.selectionText) {
      const q = p.selectionText.slice(0, 50);
      items.push(
        { label: 'Copy', click: () => clipboard.writeText(p.selectionText) },
        { label: `Search for "${q}${p.selectionText.length > 50 ? '…' : ''}"`,
          click: () => createTab((settings.searchEngine || 'https://duckduckgo.com/?q=') + encodeURIComponent(p.selectionText), true) },
        { type: 'separator' },
      );
    }

    if (p.isEditable) {
      items.push(
        { label: 'Cut',   role: 'cut'   },
        { label: 'Copy',  role: 'copy'  },
        { label: 'Paste', role: 'paste' },
        { type: 'separator' },
      );
    }

    items.push(
      { label: 'Back',    enabled: wc.canGoBack(),    click: () => wc.goBack()    },
      { label: 'Forward', enabled: wc.canGoForward(), click: () => wc.goForward() },
      { label: 'Reload',  click: () => wc.reload()    },
      { type: 'separator' },
      { label: 'Translate Page…', click: () => {
          const lang = settings.translateLang || 'en';
          const url  = wc.getURL();
          if (url && !url.startsWith('about:')) createTab(`https://translate.google.com/translate?sl=auto&tl=${lang}&u=${encodeURIComponent(url)}`, true);
        }
      },
      { type: 'separator' },
      { label: 'Save Page As…',    click: () => wc.downloadURL(wc.getURL()) },
      { label: 'View Page Source', click: () => createTab('view-source:' + wc.getURL(), true) },
      { label: 'Inspect Element',  click: () => wc.inspectElement(p.x, p.y) },
    );

    Menu.buildFromTemplate(items).popup({ window: win });
  });

  // ── Block dangerous schemes + auto-upgrade HTTP → HTTPS ───────────────────
  const _LOCAL_RE = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|::1|0\.0\.0\.0)/;
  const _guardNav = (e, url) => {
    if (/^(javascript|vbscript):/i.test(url)) { e.preventDefault(); return; }
    if (/^file:/i.test(url))                   { e.preventDefault(); return; }
    // Auto-upgrade plain HTTP to HTTPS for all non-local destinations.
    // Prevents credentials/personal data from being sent unencrypted.
    if (/^http:\/\//i.test(url)) {
      try {
        const host = new URL(url).hostname;
        if (!_LOCAL_RE.test(host) && !host.endsWith('.local')) {
          e.preventDefault();
          wc.loadURL(url.replace(/^http:/i, 'https:'));
        }
      } catch {}
    }
  };
  wc.on('will-navigate', _guardNav);
  wc.on('will-redirect', _guardNav);

  wc.on('did-start-loading', () => {
    tab.loading = true;
    // Keep the old snapshot alive — don't null it here. If a panel or context
    // menu opens while the next page is loading, the old screenshot is shown
    // rather than a blank black area.
    // tab.snapshot is cleared in did-stop-loading once the new page is ready.
    // Do NOT clear favicon here — SPA navigations (TikTok, YouTube) fire did-start-loading
    // but page-favicon-updated won't re-fire if the favicon link tag hasn't changed.
    // Favicon is cleared in did-navigate (cross-origin only) instead.
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
  });

  wc.on('did-stop-loading', () => {
    tab.loading = false;
    tab.url     = normalizeUrl(wc.getURL()) || tab.url;
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
    addHistory(tab.url, tab.title);
    // Inject floating PiP button for any page that might have video
    // Always clear any stale guard first so re-navigation gets a fresh inject.
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript('window._rawPipInjected=false;window._rawPipV3=false;').catch(()=>{});
      wc.executeJavaScript(VIDEO_PIP_INJECT).catch(() => {});
    }
    // Suppress double-scrollbar: some sites set overflow on both <html> and <body>,
    // causing Chromium to render two native scrollbars. Hiding the html-level one
    // via user-origin CSS fixes those sites without breaking normal page scrolling.
    wc.insertCSS(
      'html::-webkit-scrollbar { display: none !important; width: 0 !important; height: 0 !important; }' +
      'html { scrollbar-width: none !important; }',
      { cssOrigin: 'user' }
    ).catch(() => {});
    // Inject persistent media guard so IntersectionObserver/pause protection is
    // in place BEFORE any panel opens (fixes async race with _parkBV).
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript(PERSISTENT_MEDIA_GUARD_JS).catch(() => {});
    }

    // Re-apply enabled extensions on every page load
    const exts = settings.extensions || {};
    for (const [extId, enabled] of Object.entries(exts)) {
      if (enabled && EXT_SCRIPTS[extId]) {
        wc.executeJavaScript(EXT_SCRIPTS[extId]).catch(() => {});
      }
    }
    // Inject geolocation spoofer when enabled
    if (settings.geoEnabled && settings.geoRegion && GEO_REGIONS[settings.geoRegion]) {
      const gr = GEO_REGIONS[settings.geoRegion];
      wc.executeJavaScript(buildGeoScript(gr.lat, gr.lon)).catch(() => {});
    }
    // Background snapshot — taken immediately + refreshed at 1.5s for SPAs.
    // Keeping a fresh screenshot means panels/context-menus can show the
    // website instantly without a blank flash.
    if (id === activeId && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      const _doSnap = () => {
        if (!panelOpen && tab?.bv && !tab.bv.webContents.isDestroyed()) {
          tab.bv.webContents.capturePage().then(img => {
            tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(90).toString('base64');
          }).catch(() => {});
        }
      };
      _doSnap(); // immediate capture right after load
      setTimeout(() => { if (activeId === id) _doSnap(); }, 1500); // re-capture for SPA updates
    }
  });

  wc.on('media-started-playing', () => {
    tab.isAudible = true;
    send('tab:update', tabData(tab));
    send('audio:update', _getAudioTabs());
  });
  wc.on('media-paused', () => {
    tab.isAudible = wc.isCurrentlyAudible();
    send('tab:update', tabData(tab));
    send('audio:update', _getAudioTabs());
  });

  wc.on('did-fail-load', (_, errCode, errDesc, url) => {
    // Ignore cancelled loads (user navigated away, -3) and aborted subresources (-27)
    if (errCode === -3 || errCode === -27 || !url) return;
    tab.loading = false;
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));

    // Network-offline error codes → show offline game page
    const OFFLINE_CODES = new Set([-21, -100, -102, -105, -106, -109, -118]);
    if (OFFLINE_CODES.has(errCode)) {
      wc.loadFile(path.join(__dirname, 'offline.html'), {
        query: { url: encodeURIComponent(url) },
      }).catch(() => {});
      return;
    }

    // All other errors → inject a minimal dark error page
    const safeUrl  = (url.length > 80 ? url.slice(0, 80) + '\u2026' : url).replace(/</g, '&lt;');
    const safeCode = String(errDesc || 'ERR_FAILED').replace(/</g, '&lt;');
    const errHtml  =
      '<!doctype html><html><head><style>' +
      'body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0d0d0d;color:#ccc;' +
      'display:flex;align-items:center;justify-content:center;height:100vh;margin:0;' +
      'flex-direction:column;gap:12px;}' +
      'h2{color:#fff;font-size:18px;margin:0;font-weight:600;}' +
      'p{font-size:13px;color:#888;margin:0;text-align:center;max-width:420px;}' +
      'code{font-size:11px;color:#555;margin-top:4px;}' +
      'button{margin-top:8px;padding:8px 22px;border-radius:8px;border:1px solid rgba(255,255,255,.12);' +
      'background:rgba(255,255,255,.07);color:#ddd;cursor:pointer;font-size:13px;}' +
      'button:hover{background:rgba(255,255,255,.13);}' +
      '</style></head><body>' +
      '<svg width="40" height="40" viewBox="0 0 40 40" fill="none">' +
      '<circle cx="20" cy="20" r="19" stroke="rgba(255,255,255,.15)" stroke-width="2"/>' +
      '<path d="M20 12v10M20 28v1" stroke="#888" stroke-width="2.2" stroke-linecap="round"/>' +
      '</svg>' +
      '<h2>Can\'t reach this page</h2>' +
      '<p>' + safeUrl + '</p>' +
      '<code>' + safeCode + ' (' + errCode + ')</code>' +
      '<button onclick="history.back()">Go back</button>' +
      '</body></html>';
    wc.executeJavaScript('document.open();document.write(' + JSON.stringify(errHtml) + ');document.close()').catch(() => {});
  });

  wc.on('page-title-updated', (_, title) => {
    tab.title = title || 'Untitled';
    send('tab:update', tabData(tab));
  });

  wc.on('page-favicon-updated', (_, favs) => {
    // Only accept valid http/https URLs — data: URIs are massive, chrome:// won't load in renderer
    const validFav = (favs || []).find(f => /^https?:\/\//i.test(f));
    // Don't clear an existing favicon when SPA navigation temporarily emits empty favicons
    if (!validFav) return;
    tab.favicon = validFav;
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
  });

  wc.on('did-navigate', (_, u) => {
    const newUrl = normalizeUrl(u);
    // Only clear favicon on cross-origin navigation — same-origin SPAs (TikTok, YouTube)
    // may not re-fire page-favicon-updated so clearing would leave the tab without an icon.
    if (tab.favicon) {
      try {
        if (new URL(tab.url || '').origin !== new URL(newUrl || '').origin) tab.favicon = null;
      } catch { tab.favicon = null; }
    }
    tab.url     = newUrl;
    tab.blocked = 0;
    send('tab:update', tabData(tab));
    if (id === activeId) {
      send('nav:state', navData(tab));
      // Close any open panel/overlay so the user can interact with the new page
      send('panels:closeAll');
    }
  });

  wc.on('did-navigate-in-page', (_, u) => {
    tab.url = normalizeUrl(u);
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
    // Re-inject yt-ad add-on on YouTube SPA navigation if user has it enabled
    if (/youtube\.com/i.test(u) && settings.extensions?.['yt-ad']) {
      wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    }
  });

  wc.on('found-in-page', (_, result) => {
    send('find:result', { active: result.activeMatchOrdinal, total: result.matches });
  });

  const target = resolveUrl(url);
  if (target !== 'newtab') {
    tab.url = target; // pre-set so activateTab sees a real URL and attaches the BV
    wc.loadURL(target);
  }
  // For newtab, BV stays empty — the HTML newtab-layer in index.html shows instead

  send('tab:open', tabData(tab));
  if (activate) activateTab(id);
  return id;
}

// ── Tab close ─────────────────────────────────────────────────────────────────
function closeTab(id) {
  const tab = tabMap.get(id);
  if (!tab) return;
  try { win.removeBrowserView(tab.bv); } catch {}
  try { tab.bv.webContents.destroy();  } catch {}
  tabMap.delete(id);
  send('tab:close', id);
  if (activeId === id) {
    const keys = [...tabMap.keys()];
    if (keys.length) activateTab(keys[keys.length - 1]);
    else             createTab('newtab', true);
  }
}

// ── Zoom ──────────────────────────────────────────────────────────────────────
function setZoom(id, fn) {
  const t = tabMap.get(id);
  if (!t) return;
  t.zoom = Math.round(fn(t.zoom || 1) * 10) / 10;
  t.bv.webContents.setZoomFactor(t.zoom);
  send('zoom:current', t.zoom);
}

// ── Session / ad-blocking setup ───────────────────────────────────────────────
function setupSession(ses) {
  ses.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, cb) => {
    const tab = [...tabMap.values()].find(t => t.bv?.webContents?.id === details.webContentsId);
    if (!tab) return cb({});

    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      if (BUILTIN_WHITELIST.some(d => host === d || host.endsWith('.' + d))) return cb({});
      if (userWhitelist.some(d => host === d || host.endsWith('.' + d))) return cb({});
    } catch {}

    // Block YouTube ad-tracking/serving URLs (safe — carry no video content)
    if (YT_AD_BLOCK_PATTERNS.some(p => p.test(details.url))) {
      tab.blocked = (tab.blocked || 0) + 1;
      totalBlocked++;
      if (tab.id === activeId) send('blocked:update', { total: totalBlocked, session: tab.blocked });
      return cb({ cancel: true });
    }

    if (shouldBlock(details.url, settings.adblockEnabled)) {
      tab.blocked = (tab.blocked || 0) + 1;
      totalBlocked++;
      if (tab.id === activeId) send('blocked:update', { total: totalBlocked, session: tab.blocked });
      return cb({ cancel: true });
    }
    cb({});
  });

  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, cb) => {
    const h = { ...details.requestHeaders };

    // Helper: apply full Chrome UA spoof to headers object
    function _applyUA(headers) {
      headers['User-Agent'] = SPOOF_UA;
      headers['Sec-CH-UA'] = SPOOF_UA_HINTS;
      headers['Sec-CH-UA-Mobile'] = '?0';
      headers['Sec-CH-UA-Platform'] = '"Windows"';
      headers['Sec-CH-UA-Platform-Version'] = '"10.0.0"';
      headers['Sec-CH-UA-Arch'] = '"x86"';
      headers['Sec-CH-UA-Bitness'] = '"64"';
      headers['Sec-CH-UA-Full-Version'] = '"120.0.6099.234"';
      headers['Sec-CH-UA-Full-Version-List'] = '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.234", "Google Chrome";v="120.0.6099.234"';
    }

    // For whitelisted domains (Google, Spotify, TikTok, etc.) — spoof UA and return
    // immediately, leaving all other headers (Referer, Origin, Sec-Fetch-*) intact.
    // CRITICAL: This must apply even when the request comes from a popup/OAuth window
    // (which has no matching tab entry). Without this, Sec-CH-UA for Google sign-in
    // popup windows shows Electron's real brands, triggering "not secure browser".
    let isWhitelisted = false;
    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      isWhitelisted = BUILTIN_WHITELIST.some(d => host === d || host.endsWith('.' + d));
    } catch {}

    if (isWhitelisted) {
      _applyUA(h);
      return cb({ requestHeaders: h });
    }

    // For non-whitelisted requests from popup windows / unknown webContents
    // (no matching BV tab) — skip all header modifications to avoid breaking them.
    const tab = [...tabMap.values()].find(t => t.bv?.webContents?.id === details.webContentsId);
    if (!tab) return cb({});

    if (settings.doNotTrack)    { h['DNT'] = '1'; h['Sec-GPC'] = '1'; }
    _applyUA(h);

    // Strip cross-origin Referer to origin-only — prevents full URLs containing
    // tokens, session IDs, or personal data from leaking to third-party servers.
    if (h['Referer']) {
      try {
        const refHost = new URL(h['Referer']).hostname;
        const reqHost = new URL(details.url).hostname;
        if (refHost !== reqHost) {
          h['Referer'] = new URL(h['Referer']).origin + '/';
        }
      } catch { delete h['Referer']; }
    }

    // Remove headers that can reveal the user's real IP to proxied servers
    delete h['X-Forwarded-For'];
    delete h['Via'];
    delete h['Forwarded'];

    cb({ requestHeaders: h });
  });

  // Set session-level UA so DRM license requests (Widevine/Spotify) also use spoofed UA
  ses.setUserAgent(SPOOF_UA);

  // ── Strip CSP for bypass domains — required for preload main-world spoofing ──
  // accounts.google.com and other sign-in providers set strict Content-Security-Policy
  // headers that block inline <script> injections. Our preload.js spoofing must run in
  // the page's main JS world (contextIsolation:true forces it to use <script> injection).
  // Without stripping CSP, Google's page blocks our script and keeps seeing Electron's
  // real navigator.userAgentData.brands, triggering the "app may not be secure" error.
  const _cspBypassDomains = [
    'google.com','googleapis.com','googleusercontent.com','gstatic.com','gmail.com',
    'accounts.google.com','youtube.com','youtu.be',
    'microsoft.com','live.com','microsoftonline.com',
    'apple.com','appleid.apple.com',
    'facebook.com','instagram.com','fbcdn.net',
    'spotify.com','scdn.co','tiktok.com','tiktokv.com',
  ];
  ses.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, cb) => {
    const h = {};
    try {
      const host = new URL(details.url).hostname.toLowerCase().replace(/^www\./, '');
      const isBypass = _cspBypassDomains.some(d => host === d || host.endsWith('.' + d));
      for (const [k, v] of Object.entries(details.responseHeaders || {})) {
        const lk = k.toLowerCase();
        // Always strip COOP/COEP from every site — in a single-user browser these
        // headers serve no purpose and actively BREAK OAuth flows: when a Google/GitHub
        // login popup navigates to the callback URL on the original site, that site's
        // COOP:same-origin header severs window.opener so the parent page never gets
        // the auth code, permanently breaking Sign-in-with-Google/GitHub etc.
        if (lk === 'cross-origin-opener-policy' ||
            lk === 'cross-origin-embedder-policy') {
          continue;
        }
        // For auth/bypass domains also strip CSP, X-Frame-Options, Permissions-Policy,
        // and CORP so our preload spoofing injection works and login forms can submit.
        if (isBypass && (
            lk === 'content-security-policy' ||
            lk === 'content-security-policy-report-only' ||
            lk === 'x-frame-options' ||
            lk === 'permissions-policy' ||
            lk === 'cross-origin-resource-policy')) {
          continue;
        }
        h[k] = v;
      }
    } catch {
      return cb({});
    }
    cb({ responseHeaders: h });
  });

  // Deny tracking-risk permissions; allow safe ones.
  // NOTE: 'notifications' is deliberately NOT denied — Google's login detection
  // checks Notification.permission at the native level, and 'denied' is a strong
  // signal that this is an embedded webview, not a real browser. Notifications
  // are still blocked visually (our JS stubs return 'default'/'prompt').
  const _deniedPerms = new Set(['geolocation', 'sensors', 'background-sync', 'payment-handler', 'idle-detection', 'periodic-background-sync', 'nfc', 'bluetooth', 'camera', 'microphone', 'midi', 'publickey-credentials-create', 'publickey-credentials-get']);
  ses.setPermissionRequestHandler((_, permission, callback) => {
    // When geo spoofing is enabled, allow geolocation — our JS serves fake coords
    if (permission === 'geolocation' && settings.geoEnabled) { callback(true); return; }
    callback(!_deniedPerms.has(permission));
  });
  ses.setPermissionCheckHandler((_, permission) => {
    if (permission === 'geolocation' && settings.geoEnabled) return true;
    return !_deniedPerms.has(permission);
  });
  // Block navigation to dangerous schemes
  ses.on('will-navigate', (event, url) => {
    if (/^(javascript|vbscript|file):/i.test(url)) event.preventDefault();
  });
  ses.on('will-redirect', (event, url) => {
    if (/^(javascript|vbscript|file):/i.test(url)) event.preventDefault();
  });

  ses.on('will-download', (_, item) => {
    const entry = {
      id: Date.now(), filename: item.getFilename(),
      path: '', size: item.getTotalBytes(), received: 0, state: 'progressing',
      speed: 0, startTime: Date.now(),
    };
    let _lastBytes = 0, _lastTime = Date.now();
    downloads.unshift(entry);
    send('downloads:update', downloads);

    item.on('updated', (__, state) => {
      const now   = Date.now();
      const bytes = item.getReceivedBytes();
      const dt    = (now - _lastTime) / 1000;
      entry.speed   = dt > 0.1 ? Math.round((bytes - _lastBytes) / dt) : entry.speed;
      _lastBytes = bytes; _lastTime = now;
      entry.state    = state;
      entry.received = bytes;
      entry.path     = item.getSavePath() || entry.path;
      send('downloads:update', downloads);
    });
    item.once('done', (__, state) => {
      entry.state    = state;
      entry.speed    = 0;
      entry.received = item.getReceivedBytes();
      entry.path     = item.getSavePath() || entry.path;
      save(F.downloads, downloads.filter(d => d.state !== 'progressing'));
      send('downloads:update', downloads);
    });
  });
}

// ── App ready ─────────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  initStorage();   // app.getPath() now works
  CHROME_H = settings.compactMode ? 72 : 82;  // sync with CSS --chrome-h on startup
  // Register as default browser in Windows Default Apps (writes Registry Capabilities)
  if (process.platform === 'win32') _registerWindowsDefaultBrowser();

  win = new BrowserWindow({
    width: 1280, height: 820,
    minWidth: 640, minHeight: 400,
    frame: false,
    backgroundColor: '#080808',
    icon: path.join(__dirname, 'assets', process.platform === 'darwin' ? 'logo.icns' : 'logo.ico'),
    webPreferences: {
      nodeIntegration:  true,
      contextIsolation: false,
      webviewTag:       true,
      autoplayPolicy:   'no-user-gesture-required',
    },
    show: false,
  });

  win.loadFile(path.join(__dirname, 'index.html'));

  win.once('ready-to-show', () => {
    setupSession(session.fromPartition('persist:main'));
    setupSession(session.fromPartition('incognito')); // set up blocking/UA for private tabs
    // Explicitly set the UA on defaultSession at the session level so the underlying
    // Chromium UA string (used by Fetch, XHR, service workers) is also spoofed.
    session.defaultSession.setUserAgent(SPOOF_UA);
    // Clear Google service workers — they run in a separate context where our JS
    // overrides don't apply, so they can report real Electron identity to Google.
    const mainSes = session.fromPartition('persist:main');
    ['https://accounts.google.com','https://www.google.com','https://myaccount.google.com',
     'https://mail.google.com','https://www.youtube.com','https://play.google.com'].forEach(origin => {
      mainSes.clearStorageData({ storages: ['serviceworkers'], origin }).catch(() => {});
    });
    // Belt-and-suspenders: apply the FULL CH-UA header set to defaultSession so every
    // request (service workers, preflight, non-partitioned oauth) looks like Chrome.
    session.defaultSession.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, cb) => {
      const h = { ...details.requestHeaders };
      h['User-Agent']                  = SPOOF_UA;
      h['Sec-CH-UA']                   = SPOOF_UA_HINTS;
      h['Sec-CH-UA-Mobile']            = '?0';
      h['Sec-CH-UA-Platform']          = '"Windows"';
      h['Sec-CH-UA-Platform-Version']  = '"10.0.0"';
      h['Sec-CH-UA-Arch']              = '"x86"';
      h['Sec-CH-UA-Bitness']           = '"64"';
      h['Sec-CH-UA-Full-Version']      = '"120.0.6099.234"';
      h['Sec-CH-UA-Full-Version-List'] = '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.234", "Google Chrome";v="120.0.6099.234"';
      cb({ requestHeaders: h });
    });
    win.show();
    createTab('newtab', true);
    // Open URL passed on command line (RAW launched as default browser / open-with handler)
    const _startUrl = getArgUrl(process.argv);
    if (_startUrl) createTab(_startUrl, true);
    if (_pendingExtUrl) { createTab(_pendingExtUrl, true); _pendingExtUrl = null; }
    // Auto-check yt-dlp after UI is stable
    setTimeout(() => ytdlpCheckUpdate(), 3500);
    // Keep the cached page snapshot fresh (used by panel popups to show current page state).
    // Refreshes every 5 s while a real page is active and no panel is open.
    setInterval(() => {
      const tab = tabMap.get(activeId);
      if (!tab?.bv || panelOpen || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
      tab.bv.webContents.capturePage().then(img => {
        tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(90).toString('base64');
      }).catch(() => {});
    }, 5000);
  });

  win.on('resize', () => {
    if (panelOpen) return;
    for (const t of tabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  });

  win.on('maximize',   () => send('win:state', 'maximized'));
  win.on('unmaximize', () => send('win:state', 'normal'));
  win.on('closed',     () => { win = null; });

  // Context menu for editable fields in the main window (omnibox, newtab search, etc.)
  win.webContents.on('context-menu', (_, p) => {
    if (!p.isEditable) return;
    Menu.buildFromTemplate([
      { label: 'Emoji & Symbols', click: () => app.showEmojiPanel() },
      { type: 'separator' },
      { label: 'Cut',                  role: 'cut',              enabled: p.editFlags.canCut      },
      { label: 'Copy',                 role: 'copy',             enabled: p.editFlags.canCopy     },
      { label: 'Paste',                role: 'paste',            enabled: p.editFlags.canPaste    },
      { label: 'Paste & Match Style',  role: 'pasteAndMatchStyle', enabled: p.editFlags.canPaste  },
      { type: 'separator' },
      { label: 'Undo',                 role: 'undo',             enabled: p.editFlags.canUndo     },
      { label: 'Redo',                 role: 'redo',             enabled: p.editFlags.canRedo     },
      { type: 'separator' },
      { label: 'Select All',           role: 'selectAll',        enabled: p.editFlags.canSelectAll },
      { type: 'separator' },
      { label: 'Copy to Clipboard',    click: () => { clipboard.writeText(p.selectionText || ''); }, enabled: !!p.selectionText },
    ]).popup({ window: win });
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ── IPC: Init ─────────────────────────────────────────────────────────────────
ipcMain.handle('init', () => ({
  tabs:         [...tabMap.values()].map(tabData),
  bookmarks,
  history:      history.slice(0, 300),
  settings,
  downloads,
  platform:     process.platform,
  userWhitelist,
  blockedTotal: totalBlocked,
}));

// ── IPC: Window controls ──────────────────────────────────────────────────────
ipcMain.on('win:minimize', () => win?.minimize());
ipcMain.on('win:maximize', () => win?.isMaximized() ? win.unmaximize() : win?.maximize());
ipcMain.on('win:close',    () => win?.close());

// ── IPC: Tabs ─────────────────────────────────────────────────────────────────
ipcMain.on('tab:new', (_, url) => {
  // Strip dangerous schemes before creating tab — protects against crafted IPC calls
  const safe = (url && /^(javascript|vbscript|data|file):/i.test(url))
    ? (settings.searchEngine || 'https://duckduckgo.com/?q=') + encodeURIComponent(url)
    : (url || 'newtab');
  createTab(safe);
});
ipcMain.on('tab:switch',    (_, id)  => activateTab(id));
// ── Native tab context menu — renders above BrowserViews, no BV parking needed ──
ipcMain.on('tab:ctx', (_, { tabId, pinned }) => {
  const t = tabMap.get(tabId);
  if (!t) return;
  Menu.buildFromTemplate([
    { label: t.pinned ? 'Unpin Tab' : 'Pin Tab', click: () => { t.pinned = !t.pinned; send('tab:update', tabData(t)); send('tabs:reorder', [...tabMap.values()].map(tabData)); } },
    { label: 'Duplicate Tab', click: () => { createTab(t.url); } },
    { type: 'separator' },
    { label: 'Close Tab', click: () => { closeTab(tabId); } },
  ]).popup({ window: win });
});

ipcMain.on('tab:close',     (_, id)  => closeTab(id));
ipcMain.on('tab:duplicate', (_, id)  => { const t = tabMap.get(id); if (t) createTab(t.url); });
ipcMain.on('tab:pin',  (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  t.pinned = !t.pinned;
  // Send full tab list so renderer can reorder pinned tabs to the left
  send('tab:update', tabData(t));
  send('tabs:reorder', [...tabMap.values()].map(tabData));
});
ipcMain.on('tab:mute', (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  t.muted = !t.muted;
  t.bv.webContents.setAudioMuted(t.muted);
  send('tab:update', tabData(t));
  if (id === activeId) send('nav:state', navData(t));
  send('audio:update', _getAudioTabs());
});
ipcMain.on('tab:skip', (_, { id, secs }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const s = secs | 0;
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video');if(v)v.currentTime=Math.max(0,v.currentTime+${s});})()`,
  ).catch(() => {});
});
ipcMain.on('tab:playpause', (_, id) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video')||document.querySelector('audio');if(!v)return false;if(v.paused){v.play().catch(function(){});}else{v.pause();}return v.paused;})()`,
  ).then(paused => {
    t.paused = !!paused;
    send('audio:update', _getAudioTabs());
  }).catch(() => {});
});
ipcMain.on('tab:volume', (_, { id, volume }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const vol = Math.max(0, Math.min(1, volume));
  t.volume = vol;
  t.bv.webContents.executeJavaScript(
    `(function(){document.querySelectorAll('video,audio').forEach(function(m){m.volume=${vol};});})()`,
  ).catch(() => {});
  send('audio:update', _getAudioTabs());
});
ipcMain.on('tab:seek', (_, { id, pct }) => {
  const t = tabMap.get(id);
  if (!t?.bv) return;
  const p = Math.max(0, Math.min(1, pct));
  t.bv.webContents.executeJavaScript(
    `(function(){const v=document.querySelector('video')||document.querySelector('audio');if(v&&isFinite(v.duration)&&v.duration>0)v.currentTime=v.duration*${p};})()`,
  ).catch(() => {});
});
ipcMain.handle('tab:get-time', async (_, id) => {
  const t = tabMap.get(id);
  if (!t?.bv || t.bv.webContents.isDestroyed()) return null;
  try {
    return await t.bv.webContents.executeJavaScript(
      `(function(){const v=document.querySelector('video')||document.querySelector('audio');return v?{ct:v.currentTime,dur:v.duration}:null;})()`,
    );
  } catch { return null; }
});

// ── IPC: Navigation ───────────────────────────────────────────────────────────
// Ensure BV is attached whenever the user actively navigates (safety net).
// NOTE: Does NOT guard against t.url==='newtab' — use attachBvForNav instead.
function ensureBvAttached(t) {
  if (!t?.bv || panelOpen) return;
  try { win.addBrowserView(t.bv); } catch {}
  setBounds(t.bv);
}

// Force-attach BV for a navigation to a real URL.
// Handles the coming-from-newtab case: updates t.url eagerly so newtab-layer
// hides immediately in the renderer, then attaches the BV.
function attachBvForNav(t, url) {
  if (!t?.bv) return;
  const wasNewtab = t.url === 'newtab';
  t.url = url; // pre-set so newtab-layer hides + ensureBvAttached doesn't guard
  if (!panelOpen) {
    try { win.addBrowserView(t.bv); } catch {}
    setBounds(t.bv);
  }
  if (wasNewtab) {
    // Tell the renderer to hide newtab-layer immediately
    send('tab:update', tabData(t));
    if (t.id === activeId) send('nav:state', navData(t));
  }
}

ipcMain.on('nav:go', (_, { id, tabUrl }) => {
  const t = tabMap.get(id);
  if (!t) return;
  // Close any open panel before navigating — overlay must not block the new page
  if (panelOpen) {
    panelOpen  = false;
    panelClipX = 0;
    send('panels:closeAll');
  }
  const url = stripTracking(resolveUrl(tabUrl));
  if (url === 'newtab') {
    // Return to newtab: detach BV, update tab state
    try { win.removeBrowserView(t.bv); } catch {}
    t.url = 'newtab'; t.title = 'New Tab'; t.favicon = null;
    send('tab:update', tabData(t));
    if (id === activeId) send('nav:state', navData(t));
  } else {
    attachBvForNav(t, url);
    t.bv.webContents.loadURL(url);
  }
});
ipcMain.on('nav:back', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goBack();
});
ipcMain.on('nav:forward', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goForward();
});
ipcMain.on('nav:reload', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reload();
});
ipcMain.on('nav:reload:hard', (_, id) => {
  if (panelOpen) { panelOpen = false; panelClipX = 0; send('panels:closeAll'); }
  const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reloadIgnoringCache();
});
ipcMain.on('nav:stop',        (_, id) => tabMap.get(id)?.bv.webContents.stop());
ipcMain.on('nav:home',        (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  const hp = settings.homepage || 'newtab';
  if (hp === 'newtab') {
    try { win.removeBrowserView(t.bv); } catch {}
    t.url = 'newtab'; t.title = 'New Tab'; t.favicon = null;
    send('tab:update', tabData(t));
    if (id === activeId) send('nav:state', navData(t));
  } else {
    attachBvForNav(t, hp);
    t.bv.webContents.loadURL(hp);
  }
});

// ── Persistent media guard — injected once at page load ───────────────────────
// Wraps IntersectionObserver callbacks and HTMLVideoElement.pause so they check
// window._rbPanelOpen at *call time*. Because this runs at page load, the guards
// are in place before any panel ever opens — fixing the async timing race where
// _parkBV moved the BV offscreen before executeJavaScript could install overrides.
const PERSISTENT_MEDIA_GUARD_JS = `(function(){
  if (window._rbGuardInstalled) return;
  window._rbGuardInstalled = true;
  window._rbPanelOpen = window._rbPanelOpen || false;

  // Wrap IntersectionObserver: while panel is open, report every entry as fully
  // visible (ratio=1). YouTube's player calls .pause() inside its IO callback
  // when ratio drops to 0 — this prevents that entirely.
  if (window.IntersectionObserver) {
    var _OrigIO = window.IntersectionObserver;
    window.IntersectionObserver = function(cb, opts) {
      return new _OrigIO(function(entries, obs) {
        if (window._rbPanelOpen) {
          entries = entries.map(function(e) {
            var r = e.boundingClientRect;
            return {
              boundingClientRect: r,
              intersectionRatio:  1,
              intersectionRect:   r,
              isIntersecting:     true,
              isVisible:          true,
              contentRect:        r,
              rootBounds:         e.rootBounds,
              target:             e.target,
              time:               e.time
            };
          });
        }
        return cb(entries, obs);
      }, opts);
    };
    try { window.IntersectionObserver.prototype = _OrigIO.prototype; } catch(e) {}
  }

  // Wrap HTMLVideoElement.pause: silently drop automatic pauses while panel open.
  // Covers TikTok scroll-pause, YouTube miniplayer pause, etc.
  var _origPause = HTMLVideoElement.prototype.pause;
  HTMLVideoElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origPause.call(this);
  };

  // Wrap HTMLAudioElement.pause: same guard for audio-only players (Spotify, music).
  var _origAudioPause = HTMLAudioElement.prototype.pause;
  HTMLAudioElement.prototype.pause = function() {
    if (window._rbPanelOpen) return;
    return _origAudioPause.call(this);
  };

  // Suppress AbortError from interrupted play() calls that race with blocked pauses.
  var _origPlay = HTMLVideoElement.prototype.play;
  HTMLVideoElement.prototype.play = function() {
    var p = _origPlay.call(this);
    if (p && p.catch) p.catch(function() {});
    return p;
  };
  var _origAudioPlay = HTMLAudioElement.prototype.play;
  HTMLAudioElement.prototype.play = function() {
    var p = _origAudioPlay.call(this);
    if (p && p.catch) p.catch(function() {});
    return p;
  };

  // Block resize events while panel is open.
  // TikTok/YouTube/etc. re-read innerWidth/innerHeight on resize and rebuild their
  // virtual scroll lists — if the BV is parked at 2×2 they see a 2px viewport and
  // mark every video as off-screen. Blocking the event prevents that re-layout.
  window.addEventListener('resize', function(e) {
    if (window._rbPanelOpen) { e.stopImmediatePropagation(); }
  }, true);
})()`;

// ── Panel keep-alive: prevent videos/animations from pausing while BV is detached ──
// NOTE: PERSISTENT_MEDIA_GUARD_JS (injected at page load) handles IO/pause interception.
// This only needs to set the flag and suppress visibility/focus events.
const PANEL_KEEP_ALIVE_JS = `(function(){
  window._rbPanelOpen = true;

  // Guard video.pause() immediately — covers the case where PERSISTENT_MEDIA_GUARD_JS
  // was not yet injected (page still loading when user opens a panel).
  if (!HTMLVideoElement.prototype._rbPauseWrapped) {
    HTMLVideoElement.prototype._rbPauseWrapped = true;
    var _p0 = HTMLVideoElement.prototype.pause;
    HTMLVideoElement.prototype.pause = function () {
      if (window._rbPanelOpen) return;
      return _p0.call(this);
    };
  }
  // Guard audio.pause() — covers Spotify, music players, and any audio-only streams.
  if (!HTMLAudioElement.prototype._rbPauseWrapped) {
    HTMLAudioElement.prototype._rbPauseWrapped = true;
    var _a0 = HTMLAudioElement.prototype.pause;
    HTMLAudioElement.prototype.pause = function () {
      if (window._rbPanelOpen) return;
      return _a0.call(this);
    };
  }

  // Save real viewport dimensions BEFORE the BV is parked at 2x2.
  window._rbSavedW  = window.innerWidth;
  window._rbSavedH  = window.innerHeight;
  window._rbSavedCW = document.documentElement.clientWidth  || window._rbSavedW;
  window._rbSavedCH = document.documentElement.clientHeight || window._rbSavedH;

  function _def(obj, prop, val) {
    try { Object.defineProperty(obj, prop, { get: function(){ return val; }, configurable: true }); } catch(e) {}
  }

  // 1. innerWidth / innerHeight (YouTube, most players)
  _def(window, 'innerWidth',  window._rbSavedW);
  _def(window, 'innerHeight', window._rbSavedH);

  // 2. document.documentElement.clientWidth/clientHeight (TikTok virtual scroll)
  _def(document.documentElement, 'clientWidth',  window._rbSavedCW);
  _def(document.documentElement, 'clientHeight', window._rbSavedCH);

  // 3. visualViewport API (TikTok, Instagram Reels)
  if (window.visualViewport) {
    _def(window.visualViewport, 'width',      window._rbSavedW);
    _def(window.visualViewport, 'height',     window._rbSavedH);
    _def(window.visualViewport, 'scale',      1);
    _def(window.visualViewport, 'offsetTop',  0);
    _def(window.visualViewport, 'offsetLeft', 0);
  }

  // 4. Wrap ResizeObserver — callbacks fire with real 2x2 sizes and cause
  //    TikTok to unmount the current video and rebuild the scroll layout.
  //    Returning without calling the original callback prevents that reflow.
  if (window.ResizeObserver && !window._rbOrigRO) {
    window._rbOrigRO = window.ResizeObserver;
    function _PatchedRO(cb) {
      var _patched = function(entries, obs) {
        if (window._rbPanelOpen) return; // suppress while panel is open
        cb.call(this, entries, obs);
      };
      return new window._rbOrigRO(_patched);
    }
    _PatchedRO.prototype = window._rbOrigRO.prototype;
    window.ResizeObserver = _PatchedRO;
  }

  // 5. Block resize event so virtual scrollers don't recalculate grid layout.
  if (!window._rbResizeBlock) {
    window._rbResizeBlock = function(e) { e.stopImmediatePropagation(); };
    window.addEventListener('resize', window._rbResizeBlock, true);
  }

  // 6. Visibility / focus API
  _def(document, 'hidden',          false);
  _def(document, 'visibilityState', 'visible');
  if (!window._rbOrigHasFocus) {
    window._rbOrigHasFocus = document.hasFocus.bind(document);
    document.hasFocus = function() { return true; };
  }

  // 7. Block events that signal the page is going to the background.
  if (!window._rbVCBlock) {
    window._rbVCBlock = function(e) { e.stopImmediatePropagation(); };
    document.addEventListener('visibilitychange', window._rbVCBlock, true);
    window.addEventListener('blur',     window._rbVCBlock, true);
    window.addEventListener('pagehide', window._rbVCBlock, true);
    window.addEventListener('freeze',   window._rbVCBlock, true);
  }
})()`;
const PANEL_RESTORE_ALIVE_JS = `(function(){
  window._rbPanelOpen = false;

  // 1. Restore innerWidth / innerHeight
  try { delete window.innerWidth;  } catch {}
  try { delete window.innerHeight; } catch {}
  delete window._rbSavedW; delete window._rbSavedH;

  // 2. Restore document.documentElement.clientWidth/clientHeight
  try { delete document.documentElement.clientWidth;  } catch {}
  try { delete document.documentElement.clientHeight; } catch {}
  delete window._rbSavedCW; delete window._rbSavedCH;

  // 3. Restore visualViewport
  if (window.visualViewport) {
    try { delete window.visualViewport.width;      } catch {}
    try { delete window.visualViewport.height;     } catch {}
    try { delete window.visualViewport.scale;      } catch {}
    try { delete window.visualViewport.offsetTop;  } catch {}
    try { delete window.visualViewport.offsetLeft; } catch {}
  }

  // 4. Restore ResizeObserver
  if (window._rbOrigRO) {
    window.ResizeObserver = window._rbOrigRO;
    delete window._rbOrigRO;
  }

  // 5. Remove resize blocker, then fire real resize so layouts rebuild.
  if (window._rbResizeBlock) {
    window.removeEventListener('resize', window._rbResizeBlock, true);
    delete window._rbResizeBlock;
  }
  setTimeout(function() {
    try { if (!window._rbPanelOpen) window.dispatchEvent(new Event('resize')); } catch {}
  }, 0);

  // 6. Restore visibility API
  try { delete document.hidden; } catch {}
  try { delete document.visibilityState; } catch {}

  // 7. Restore hasFocus
  if (window._rbOrigHasFocus) {
    document.hasFocus = window._rbOrigHasFocus;
    delete window._rbOrigHasFocus;
  }

  // 8. Remove event blockers
  if (window._rbVCBlock) {
    document.removeEventListener('visibilitychange', window._rbVCBlock, true);
    window.removeEventListener('blur',     window._rbVCBlock, true);
    window.removeEventListener('pagehide', window._rbVCBlock, true);
    window.removeEventListener('freeze',   window._rbVCBlock, true);
    delete window._rbVCBlock;
  }
})()`;

// ── Geolocation spoofing ───────────────────────────────────────────────────────
const GEO_REGIONS = {
  // North America
  'new-york':    { lat:  40.7128, lon:  -74.0060, label: 'New York',       flag: '🇺🇸', region: 'North America' },
  'los-angeles': { lat:  34.0522, lon: -118.2437, label: 'Los Angeles',    flag: '🇺🇸', region: 'North America' },
  'chicago':     { lat:  41.8781, lon:  -87.6298, label: 'Chicago',        flag: '🇺🇸', region: 'North America' },
  'miami':       { lat:  25.7617, lon:  -80.1918, label: 'Miami',          flag: '🇺🇸', region: 'North America' },
  'dallas':      { lat:  32.7767, lon:  -96.7970, label: 'Dallas',         flag: '🇺🇸', region: 'North America' },
  'seattle':     { lat:  47.6062, lon: -122.3321, label: 'Seattle',        flag: '🇺🇸', region: 'North America' },
  'atlanta':     { lat:  33.7490, lon:  -84.3880, label: 'Atlanta',        flag: '🇺🇸', region: 'North America' },
  'toronto':     { lat:  43.6511, lon:  -79.3832, label: 'Toronto',        flag: '🇨🇦', region: 'North America' },
  'vancouver':   { lat:  49.2827, lon: -123.1207, label: 'Vancouver',      flag: '🇨🇦', region: 'North America' },
  'mexico-city': { lat:  19.4326, lon:  -99.1332, label: 'Mexico City',    flag: '🇲🇽', region: 'North America' },
  // Europe
  'london':      { lat:  51.5074, lon:   -0.1278, label: 'London',         flag: '🇬🇧', region: 'Europe' },
  'manchester':  { lat:  53.4808, lon:   -2.2426, label: 'Manchester',     flag: '🇬🇧', region: 'Europe' },
  'paris':       { lat:  48.8566, lon:    2.3522, label: 'Paris',          flag: '🇫🇷', region: 'Europe' },
  'berlin':      { lat:  52.5200, lon:   13.4050, label: 'Berlin',         flag: '🇩🇪', region: 'Europe' },
  'frankfurt':   { lat:  50.1109, lon:    8.6821, label: 'Frankfurt',      flag: '🇩🇪', region: 'Europe' },
  'amsterdam':   { lat:  52.3676, lon:    4.9041, label: 'Amsterdam',      flag: '🇳🇱', region: 'Europe' },
  'rome':        { lat:  41.9028, lon:   12.4964, label: 'Rome',           flag: '🇮🇹', region: 'Europe' },
  'madrid':      { lat:  40.4168, lon:   -3.7038, label: 'Madrid',         flag: '🇪🇸', region: 'Europe' },
  'stockholm':   { lat:  59.3293, lon:   18.0686, label: 'Stockholm',      flag: '🇸🇪', region: 'Europe' },
  'warsaw':      { lat:  52.2297, lon:   21.0122, label: 'Warsaw',         flag: '🇵🇱', region: 'Europe' },
  'vienna':      { lat:  48.2082, lon:   16.3738, label: 'Vienna',         flag: '🇦🇹', region: 'Europe' },
  'zurich':      { lat:  47.3769, lon:    8.5417, label: 'Zurich',         flag: '🇨🇭', region: 'Europe' },
  'brussels':    { lat:  50.8503, lon:    4.3517, label: 'Brussels',       flag: '🇧🇪', region: 'Europe' },
  'prague':      { lat:  50.0755, lon:   14.4378, label: 'Prague',         flag: '🇨🇿', region: 'Europe' },
  // Asia / Pacific
  'tokyo':       { lat:  35.6762, lon:  139.6503, label: 'Tokyo',          flag: '🇯🇵', region: 'Asia / Pacific' },
  'osaka':       { lat:  34.6937, lon:  135.5023, label: 'Osaka',          flag: '🇯🇵', region: 'Asia / Pacific' },
  'seoul':       { lat:  37.5665, lon:  126.9780, label: 'Seoul',          flag: '🇰🇷', region: 'Asia / Pacific' },
  'singapore':   { lat:   1.3521, lon:  103.8198, label: 'Singapore',      flag: '🇸🇬', region: 'Asia / Pacific' },
  'hong-kong':   { lat:  22.3193, lon:  114.1694, label: 'Hong Kong',      flag: '🇭🇰', region: 'Asia / Pacific' },
  'shanghai':    { lat:  31.2304, lon:  121.4737, label: 'Shanghai',       flag: '🇨🇳', region: 'Asia / Pacific' },
  'bangkok':     { lat:  13.7563, lon:  100.5018, label: 'Bangkok',        flag: '🇹🇭', region: 'Asia / Pacific' },
  'jakarta':     { lat:  -6.2088, lon:  106.8456, label: 'Jakarta',        flag: '🇮🇩', region: 'Asia / Pacific' },
  'kl':          { lat:   3.1390, lon:  101.6869, label: 'Kuala Lumpur',   flag: '🇲🇾', region: 'Asia / Pacific' },
  'mumbai':      { lat:  19.0760, lon:   72.8777, label: 'Mumbai',         flag: '🇮🇳', region: 'Asia / Pacific' },
  'delhi':       { lat:  28.6139, lon:   77.2090, label: 'Delhi',          flag: '🇮🇳', region: 'Asia / Pacific' },
  'dubai':       { lat:  25.2048, lon:   55.2708, label: 'Dubai',          flag: '🇦🇪', region: 'Asia / Pacific' },
  'sydney':      { lat: -33.8688, lon:  151.2093, label: 'Sydney',         flag: '🇦🇺', region: 'Asia / Pacific' },
  'melbourne':   { lat: -37.8136, lon:  144.9631, label: 'Melbourne',      flag: '🇦🇺', region: 'Asia / Pacific' },
  'auckland':    { lat: -36.8485, lon:  174.7633, label: 'Auckland',       flag: '🇳🇿', region: 'Asia / Pacific' },
  // South America
  'sao-paulo':   { lat: -23.5505, lon:  -46.6333, label: 'São Paulo',      flag: '🇧🇷', region: 'South America' },
  'rio':         { lat: -22.9068, lon:  -43.1729, label: 'Rio de Janeiro', flag: '🇧🇷', region: 'South America' },
  'buenos-aires':{ lat: -34.6037, lon:  -58.3816, label: 'Buenos Aires',   flag: '🇦🇷', region: 'South America' },
  'bogota':      { lat:   4.7110, lon:  -74.0721, label: 'Bogotá',         flag: '🇨🇴', region: 'South America' },
  'lima':        { lat: -12.0464, lon:  -77.0428, label: 'Lima',           flag: '🇵🇪', region: 'South America' },
  'santiago':    { lat: -33.4489, lon:  -70.6693, label: 'Santiago',       flag: '🇨🇱', region: 'South America' },
  // Africa / Middle East
  'cairo':       { lat:  30.0444, lon:   31.2357, label: 'Cairo',          flag: '🇪🇬', region: 'Africa / Middle East' },
  'lagos':       { lat:   6.5244, lon:    3.3792, label: 'Lagos',          flag: '🇳🇬', region: 'Africa / Middle East' },
  'johannesburg':{ lat: -26.2041, lon:   28.0473, label: 'Johannesburg',   flag: '🇿🇦', region: 'Africa / Middle East' },
  'nairobi':     { lat:  -1.2921, lon:   36.8219, label: 'Nairobi',        flag: '🇰🇪', region: 'Africa / Middle East' },
  'tel-aviv':    { lat:  32.0853, lon:   34.7818, label: 'Tel Aviv',       flag: '🇮🇱', region: 'Africa / Middle East' },
  'riyadh':      { lat:  24.7136, lon:   46.6753, label: 'Riyadh',         flag: '🇸🇦', region: 'Africa / Middle East' },
};
function buildGeoScript(lat, lon) {
  return `(function(){
  var _r={coords:{latitude:${lat},longitude:${lon},accuracy:45,altitude:null,altitudeAccuracy:null,heading:null,speed:null},timestamp:Date.now()};
  var _g={getCurrentPosition:function(ok){setTimeout(function(){ok(_r);},80);},watchPosition:function(ok){setTimeout(function(){ok(_r);},80);return 1;},clearWatch:function(){}};
  try{Object.defineProperty(navigator,'geolocation',{get:function(){return _g;},configurable:true});}catch(e){}
})()`;
}

// ── IPC: Panels — detach/reattach BrowserView so HTML panels are visible ──────
// ── Shared panel-open helper ─────────────────────────────────────────────────
// WHY SLIDE-BELOW INSTEAD OF REMOVE:
//   removeBrowserView() detaches the RenderWidget from the GPU compositor’s
//   frame sink — a C++ operation that suspends the video decoder before any
//   JS can run. No JS flag or CLI switch prevents this.
//
//   Instead: slide the BV below the bottom edge of the window (y ≥ winH)
//   while keeping it ATTACHED. The compositor frame sink stays live, video
//   keeps playing, and the window’s full visible area is free for the
//   BrowserWindow HTML panels to render into. The snapshot element
//   (position:absolute; inset:0) covers the entire content area so the
//   user never sees the half-visible BV strip that the old resize caused.
async function _openPanel(tab) {
  if (!tab?.bv || tab.url === 'newtab') return;
  const bv = tab.bv;
  const wc = bv.webContents;
  if (wc.isDestroyed()) return;

  // Step 1: Inject keep-alive JS FIRST — sets _rbPanelOpen=true so video.pause()
  // is blocked before any resize fires. Must precede capturePage().
  await wc.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
  if (!panelOpen) return;

  // Step 2: Capture screenshot at full bounds.
  try {
    const img = await wc.capturePage();
    if (img) tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(90).toString('base64');
  } catch {}
  if (!panelOpen) return;

  // Step 3: Send snapshot to renderer and WAIT for it to confirm the canvas is
  // drawn (IPC ACK: 'panel:snapshot:drawn'). The canvas paints silently behind
  // the BV while the BV is still on top. Once the ACK arrives, the canvas is
  // pixel-perfect on screen — we then park the BV and the canvas is revealed
  // instantly with zero dark gap. No CSS blanker is needed: skipping it
  // eliminates the BV backgroundColor (#080808) flash that caused the website
  // to appear to "hide".
  if (tab.snapshot) {
    send('panel:snapshot', tab.snapshot);
    await new Promise(resolve => {
      const t = setTimeout(resolve, 200); // 200 ms safety fallback
      ipcMain.once('panel:snapshot:drawn', () => { clearTimeout(t); resolve(); });
    });
  }
  if (!panelOpen) return;

  // Step 4: Park BV off-screen. Canvas already drawn → reveals immediately.
  // incrementCapturerCount keeps video decoder running at full resolution.
  _parkBV(bv);

  // Step 5: Live capture loop — streams off-screen frames so video stays live.
  tab._mediaKeepAlive = true;
  (async () => {
    while (panelOpen && !wc.isDestroyed() && tab._mediaKeepAlive) {
      try {
        const frame = await wc.capturePage();
        if (frame && panelOpen && tab._mediaKeepAlive) {
          send('panel:snapshot', 'data:image/jpeg;base64,' +
            frame.toJPEG(75).toString('base64'));
        }
      } catch {}
      await new Promise(r => setTimeout(r, 16));
    }
  })();
}

ipcMain.on('panel:show', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:quick', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:keepalive', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:fast', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:nowait', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:sync', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});
ipcMain.on('panel:show:instant', () => {
  panelOpen = true;
  _openPanel(tabMap.get(activeId));
});

// Resize BV to leave right-side room for the open panel (so panel HTML shows above BV)
ipcMain.on('panel:clip', (_, x) => {
  panelOpen  = true;
  panelClipX = Math.max(0, x || 0);
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    try { win.addBrowserView(tab.bv); } catch {}
    setBounds(tab.bv);
  }
});

// ── Omnibox dropdown — instant BV park/restore (no async screenshot) ────────
// _openPanel is async (capturePage before parking) which means the BV covers
// the suggestion list for ~300ms. These dedicated handlers park/restore
// synchronously so the dropdown is immediately visible above the BV.
ipcMain.on('omni:drop:show', () => {
  if (panelOpen) return; // panel already parked the BV — don't double-increment
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  _parkBV(tab.bv);
});
ipcMain.on('omni:drop:hide', () => {
  if (panelOpen) return; // panel will restore the BV when it closes — don't decrement early
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  _unparkBV(tab.bv);
});

ipcMain.on('panel:hide', async () => {
  panelOpen = false;
  _panelSeq = 0;    // invalidate any pending async panel:show:fast chains
  panelClipX = 0;   // always restore full BV width
  // Clear any pending panel:snapshot:drawn listener so it doesn't fire later
  ipcMain.removeAllListeners('panel:snapshot:drawn');
  const tab = tabMap.get(activeId);
  if (tab?._mediaKeepAlive) { tab._mediaKeepAlive = null; } // stops the capture loop
  if (tab?.bv && tab.url !== 'newtab') {
    // Unpark: decrement capturer count then restore full-width bounds
    _unparkBV(tab.bv);
    // Restore visibility overrides and dispatch resize so layouts rebuild
    tab.bv.webContents.executeJavaScript(PANEL_RESTORE_ALIVE_JS).catch(() => {});
    // Resume any media that was interrupted while the BV was parked
    tab.bv.webContents.executeJavaScript(`(function(){
      try{document.querySelectorAll('video,audio').forEach(function(m){
        if(m.paused&&m.readyState>0&&m.currentTime>0&&!m.ended){
          m.play().catch(function(){});
        }
      });}catch(e){}
    })()`).catch(() => {});
  }
  send('panel:snapshot:clear');
});

// ── Sidebar add-link modal ──────────────────────────────────────────────────
// Must capture a screenshot and show it before parking the BV, otherwise the
// user sees the wallpaper/background instead of the website they were on.
ipcMain.on('sidebar:modal:open', async () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab' || tab.bv.webContents.isDestroyed()) return;
  const wc = tab.bv.webContents;
  // Capture screenshot at current full bounds
  try {
    const img = await wc.capturePage();
    if (img) tab.snapshot = 'data:image/jpeg;base64,' + img.toJPEG(90).toString('base64');
  } catch {}
  // Send snapshot to renderer, wait for it to confirm canvas is drawn, then park.
  // This ensures the canvas is visible the instant the BV moves offscreen.
  if (tab.snapshot) {
    send('panel:snapshot', tab.snapshot);
    await new Promise(resolve => {
      const t = setTimeout(resolve, 200);
      ipcMain.once('panel:snapshot:drawn', () => { clearTimeout(t); resolve(); });
    });
  }
  _parkBV(tab.bv);
});
ipcMain.on('sidebar:modal:close', () => {
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') {
    try { if (tab.bv.webContents.isDestroyed()) return; } catch { return; }
    _unparkBV(tab.bv);
  }
  send('panel:snapshot:clear');
});

ipcMain.on('sidebar:toggle', (_, show) => {
  sidebarOn = !!show;
  // Update bounds for all tabs so sidebar offset is applied immediately
  if (!panelOpen) {
    for (const t of tabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  }
});

// ── IPC: Snip tool ────────────────────────────────────────────────────────────
ipcMain.on('snip:start', () => {
  panelOpen = true;
  const seq = ++_panelSeq;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') { send('snip:ready', null); return; }
  const _sbv = tab.bv;
  const _swc = _sbv.webContents;
  // Inject keep-alive guard FIRST so video never pauses during capture or park.
  _swc.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {}).finally(() => {
    if (!panelOpen || _panelSeq !== seq) return;
    _swc.capturePage().then(img => {
      if (!panelOpen || _panelSeq !== seq) return;
      _parkBV(_sbv);
      send('snip:ready', img.toDataURL());
    }).catch(() => {
      if (!panelOpen || _panelSeq !== seq) return;
      _parkBV(_sbv);
      send('snip:ready', null);
    });
  });
});
ipcMain.on('snip:cancel', () => {
  panelOpen = false;
  _panelSeq = 0;
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') try { win.addBrowserView(tab.bv); setBounds(tab.bv); } catch {}
});
ipcMain.on('snip:save', async (_, dataURL) => {
  panelOpen = false;
  _panelSeq = 0;
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') try { win.addBrowserView(tab.bv); setBounds(tab.bv); } catch {}
  try {
    const buf = Buffer.from(dataURL.replace(/^data:image\/png;base64,/, ''), 'base64');
    const ts  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const def = path.join(app.getPath('pictures'), `snip-${ts}.png`);
    const { canceled, filePath: fp } = await dialog.showSaveDialog(win, {
      title: 'Save Snip', defaultPath: def,
      filters: [{ name: 'PNG Image', extensions: ['png'] }],
    });
    if (!canceled && fp) fs.writeFile(fp, buf, err => send('toast', err ? 'Failed to save snip' : 'Snip saved', err ? 'err' : 'teal'));
  } catch {}
});

// ── IPC: Bookmarks ────────────────────────────────────────────────────────────
ipcMain.on('bookmark:add', (_, { url, title, favicon }) => {
  bookmarks.unshift({ id: Date.now(), url, title, favicon, ts: Date.now() });
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});
ipcMain.on('bookmark:remove', (_, id) => {
  bookmarks = bookmarks.filter(b => b.id !== id);
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});
// Bulk import bookmarks from external source (setup import step)
ipcMain.on('bookmarks:bulk-add', (_, items) => {
  if (!Array.isArray(items) || !items.length) return;
  const existingUrls = new Set(bookmarks.map(b => b.url));
  const newOnes = items
    .filter(b =>
      b && typeof b.url === 'string' && typeof b.title === 'string' &&
      // Strict: only http/https URLs — never allow javascript:, file:, data:, etc.
      /^https?:\/\//i.test(b.url) &&
      b.url.length < 2048 &&
      !existingUrls.has(b.url)
    )
    .map((b, i) => ({
      id: Date.now() + i,
      url: b.url,
      // Sanitize title — strip any HTML/control chars
      title: String(b.title).replace(/[\x00-\x1f<>"']/g, '').slice(0, 300) || 'Bookmark',
      favicon: null, ts: Date.now()
    }));
  if (!newOnes.length) return;
  bookmarks.push(...newOnes);
  save(F.bookmarks, bookmarks);
  send('bookmarks:set', bookmarks);
});

// ── Helpers: LZ4 block decoder (for Firefox mozlz4 bookmark backups) ──────────
function lz4BlockDecode(src, outputSize) {
  const dst = Buffer.alloc(outputSize);
  let si = 0, di = 0;
  while (si < src.length) {
    const token = src[si++];
    let litLen = token >>> 4;
    if (litLen === 15) { let x; do { x = src[si++]; litLen += x; } while (x === 255); }
    src.copy(dst, di, si, si + litLen); si += litLen; di += litLen;
    if (si >= src.length) break;
    const offset = src[si] | (src[si + 1] << 8); si += 2;
    let matchLen = (token & 0xf) + 4;
    if ((token & 0xf) === 15) { let x; do { x = src[si++]; matchLen += x; } while (x === 255); }
    const ms = di - offset;
    for (let k = 0; k < matchLen; k++) dst[di++] = dst[ms + k];
  }
  return dst.slice(0, di);
}
function decodeMozlz4(buf) {
  if (buf.slice(0, 8).toString('binary') !== 'mozLz40\0') throw new Error('Not mozlz4');
  const uncompressedSize = buf.readUInt32LE(8);
  // Cap at 64 MB — a real Firefox bookmark file is never this large.
  // Prevents DoS via malformed/crafted mozlz4 file.
  if (uncompressedSize > 64 * 1024 * 1024) throw new Error('mozlz4: output too large, refusing to decode');
  return lz4BlockDecode(buf.slice(12), uncompressedSize);
}
function extractFirefoxBookmarks(node, out = []) {
  if (!node) return out;
  if (node.type === 'text/x-moz-place' && node.uri && node.title &&
      !/^(place:|javascript:|vbscript:)/i.test(node.uri) && /^https?:\/\//i.test(node.uri)) {
    out.push({ title: String(node.title).slice(0, 500), url: node.uri });
  }
  if (Array.isArray(node.children)) node.children.forEach(c => extractFirefoxBookmarks(c, out));
  return out;
}
function findFirefoxBookmarkBackup() {
  const home = os.homedir();
  const pl   = process.platform;
  const base = pl === 'win32'  ? path.join(os.homedir(), 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
             : pl === 'darwin' ? path.join(home, 'Library', 'Application Support', 'Firefox', 'Profiles')
                               : path.join(home, '.mozilla', 'firefox');
  return findMozillaBookmarkBackup([base]);
}
// Generic finder: searches a list of profile-base directories for mozlz4 backups.
// Handles all Firefox forks that use the same profile layout.
function findMozillaBookmarkBackup(bases) {
  for (const base of (Array.isArray(bases) ? bases : [bases])) {
    if (!base) continue;
    try {
      if (!fs.existsSync(base)) continue;
      const profiles = fs.readdirSync(base);
      for (const prof of profiles) {
        if (prof === 'Crash Reports' || prof === 'crash-reports') continue;
        const bbDir = path.join(base, prof, 'bookmarkbackups');
        try {
          const files = fs.readdirSync(bbDir).filter(f => f.endsWith('.jsonlz4') || f.endsWith('.baklz4'));
          if (!files.length) continue;
          // Use the most recently modified backup
          const best = files.map(f => {
            try { return { f, mt: fs.statSync(path.join(bbDir, f)).mtimeMs }; } catch { return null; }
          }).filter(Boolean).sort((a, b) => b.mt - a.mt)[0];
          if (best) return path.join(bbDir, best.f);
        } catch {}
      }
    } catch {}
  }
  return null;
}
// Build profile-base path list for a Firefox-family browser given its app-data dir name(s)
function getMozProfileBases(winNames, macNames, linuxNames) {
  const home = os.homedir();
  const pl   = process.platform;
  const roaming = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const local   = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  if (pl === 'win32')  return winNames.map(n => path.join(roaming, n));
  if (pl === 'darwin') return macNames.map(n => path.join(home, 'Library', 'Application Support', n));
  return linuxNames.map(n => path.join(home, n));
}
function* walkDir(dir) {
  try {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) yield* walkDir(full);
      else yield full;
    }
  } catch {}
}

// ── Helper: find Chromium Bookmarks file across all profiles ──────────────────
// chromiumPaths stores paths like: .../User Data/Default/Bookmarks
// If the user's active profile isn't 'Default', we scan siblings too.
function _findChromiumBookmarks(defaultPath) {
  if (!defaultPath) return null;
  try {
    if (fs.existsSync(defaultPath)) return defaultPath;
    // Walk up two levels to get the User Data directory
    const userData = path.dirname(path.dirname(defaultPath));
    if (!fs.existsSync(userData)) return null;
    const entries = fs.readdirSync(userData, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      if (!/^(Default|Profile \d+|Guest Profile|System Profile)$/.test(ent.name)) continue;
      const bmPath = path.join(userData, ent.name, 'Bookmarks');
      if (fs.existsSync(bmPath)) return bmPath;
    }
  } catch {}
  return null;
}

// ── Windows: register as default browser in system Default Apps ───────────────
// Follows the exact same registry structure that Chrome/Edge use so Windows
// 10/11 recognises Raw Browser in Settings › Default Apps.
//
// Structure (all under HKCU so no admin required):
//   HKCU\Software\Classes\RawBrowserHTML           ← ProgID (URL + file handler)
//   HKCU\Software\Clients\StartMenuInternet\Raw Browser   ← StartMenuInternet tree
//   HKCU\Software\RegisteredApplications           ← makes it appear in Default Apps UI
function _registerWindowsDefaultBrowser() {
  if (process.platform !== 'win32') return;
  try {
    const { execSync } = require('child_process');
    const exePath = app.getPath('exe');
    const progID  = 'RawBrowserHTML'; // single ProgID for both URL + file types (mirrors ChromeHTML)
    const appKey  = `Software\\Clients\\StartMenuInternet\\Raw Browser`;
    const capKey  = `${appKey}\\Capabilities`;
    const clsKey  = `Software\\Classes\\${progID}`;

    const regSZ = (hive, key, name, val) => {
      const escaped = String(val).replace(/"/g, '\\"');
      const n = name === '' ? '/ve' : `/v "${name}"`;
      execSync(`reg add "${hive}\\${key}" ${n} /t REG_SZ /d "${escaped}" /f`,
               { windowsHide: true, stdio: 'ignore' });
    };
    const regDW = (hive, key, name, val) => {
      execSync(`reg add "${hive}\\${key}" /v "${name}" /t REG_DWORD /d "${val}" /f`,
               { windowsHide: true, stdio: 'ignore' });
    };

    // ── ProgID — describes how to open URLs and HTML files ──────────────────
    regSZ('HKCU', clsKey, '', 'Raw Browser HTML Document');
    regSZ('HKCU', `${clsKey}\\DefaultIcon`, '', `"${exePath}",0`);
    regSZ('HKCU', `${clsKey}\\shell\\open\\command`, '', `"${exePath}" "%1"`);
    // Mark as a URL handler for http + https
    regSZ('HKCU', clsKey, 'URL Protocol', '');

    // ── StartMenuInternet tree — required so Windows lists the app ───────────
    regSZ('HKCU', appKey, '', 'Raw Browser');
    regSZ('HKCU', `${appKey}\\DefaultIcon`, '', `"${exePath}",0`);
    regSZ('HKCU', `${appKey}\\shell\\open\\command`, '', `"${exePath}"`);
    regDW('HKCU', `${appKey}\\InstallInfo`, 'IconsVisible', 1);
    regSZ('HKCU', `${appKey}\\StartMenu`, '', 'Raw Browser');

    // ── Capabilities — what Windows reads from RegisteredApplications ────────
    regSZ('HKCU', capKey, 'ApplicationName', 'Raw Browser');
    regSZ('HKCU', capKey, 'ApplicationIcon', `"${exePath}",0`);
    regSZ('HKCU', capKey, 'ApplicationDescription', 'Privacy-first browser — built-in ad blocking, no tracking');
    // URL associations
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'ftp',   progID);
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'http',  progID);
    regSZ('HKCU', `${capKey}\\URLAssociations`, 'https', progID);
    // File associations
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.htm',   progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.html',  progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.xhtml', progID);
    regSZ('HKCU', `${capKey}\\FileAssociations`, '.pdf',   progID);

    // ── RegisteredApplications — the entry that makes it appear in Default Apps
    // Value must be the path WITHOUT the HKCU\ prefix
    regSZ('HKCU', 'Software\\RegisteredApplications', 'Raw Browser', capKey);
  } catch { /* fail silently — restricted environments */ }
}

// ── IPC: Default browser ──────────────────────────────────────────────────────
ipcMain.on('browser:set-default', () => {
  app.setAsDefaultProtocolClient('https');
  app.setAsDefaultProtocolClient('http');
  app.setAsDefaultProtocolClient('ftp');
  if (process.platform === 'win32') {
    _registerWindowsDefaultBrowser();
    shell.openExternal('ms-settings:defaultapps').catch(() => {});
  } else if (process.platform === 'darwin') {
    shell.openExternal('x-apple.systempreferences:com.apple.preference.general').catch(() => {});
  }
});
ipcMain.handle('browser:is-default', () => app.isDefaultProtocolClient('https'));

// ── IPC: Browser data import ──────────────────────────────────────────────────
// Strict allowlist — never let the renderer supply an arbitrary string to a file-read path.
const _MOZ_BROWSER_IDS = new Set(['firefox','librewolf','zen','waterfox','floorp','palemoon','basilisk','iceweasel']);
const _CHROME_BROWSER_IDS = new Set(['chrome','edge','brave','opera','vivaldi','arc','thorium','chromium','opera-gx','yandex']);
const _SPECIAL_IDS = new Set(['safari','ie']);

function _buildChromiumPaths() {
  const home = os.homedir();
  const pl   = process.platform;
  const local = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
  const roam  = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const bm = n => `${n}${path.sep}Bookmarks`; // append Bookmarks filename
  function w(p) { return path.join(local, p, 'Bookmarks'); }
  function m(p) { return path.join(home, 'Library', 'Application Support', p, 'Bookmarks'); }
  function l(p) { return path.join(home, p, 'Bookmarks'); }
  const table = {
    chrome:    { win: w('Google\\Chrome\\User Data\\Default'),   mac: m('Google/Chrome/Default'),         lin: l('.config/google-chrome/Default') },
    edge:      { win: w('Microsoft\\Edge\\User Data\\Default'),  mac: m('Microsoft Edge/Default'),         lin: l('.config/microsoft-edge/Default') },
    brave:     { win: w('BraveSoftware\\Brave-Browser\\User Data\\Default'), mac: m('BraveSoftware/Brave-Browser/Default'), lin: l('.config/BraveSoftware/Brave-Browser/Default') },
    opera:     { win: path.join(roam, 'Opera Software', 'Opera Stable', 'Bookmarks'), mac: m('com.operasoftware.Opera'), lin: l('.config/opera') + '/Bookmarks' },
    'opera-gx':{ win: path.join(roam, 'Opera Software', 'Opera GX Stable', 'Bookmarks'), mac: m('com.operasoftware.OperaGX'), lin: l('.config/opera') + '/Bookmarks' },
    vivaldi:   { win: w('Vivaldi\\User Data\\Default'),          mac: m('Vivaldi/Default'),                lin: l('.config/vivaldi/Default') },
    arc:       { win: w('Arc\\User Data\\Default'),              mac: m('Arc/User Data/Default'),          lin: null },
    thorium:   { win: w('Thorium\\User Data\\Default'),          mac: m('Thorium/Default'),                lin: l('.config/thorium/Default') },
    chromium:  { win: w('Chromium\\User Data\\Default'),         mac: m('Chromium/Default'),               lin: l('.config/chromium/Default') },
    yandex:    { win: w('Yandex\\YandexBrowser\\User Data\\Default'), mac: m('Yandex/YandexBrowser/Default'), lin: l('.config/yandex-browser-beta/Default') },
  };
  const result = {};
  for (const [id, paths] of Object.entries(table)) {
    result[id] = pl === 'win32' ? paths.win : pl === 'darwin' ? paths.mac : paths.lin;
  }
  return result;
}
function _buildMozillaForkBases() {
  // Each entry: list of profile BASE directories to search
  return {
    firefox:   getMozProfileBases(['Mozilla\\Firefox\\Profiles'], ['Firefox/Profiles'], ['.mozilla/firefox']),
    librewolf: getMozProfileBases(['LibreWolf\\Profiles'], ['LibreWolf/Profiles'], ['.librewolf']),
    zen:       getMozProfileBases(['Zen\\Profiles', 'Zen Browser\\Profiles'], ['Zen Browser/Profiles'], ['.zen']),
    waterfox:  getMozProfileBases(['Waterfox\\Profiles'], ['Waterfox/Profiles'], ['.waterfox']),
    floorp:    getMozProfileBases(['Floorp\\Profiles'], ['Floorp/Profiles'], ['.floorp']),
    palemoon:  getMozProfileBases(['Moonchild Productions\\Pale Moon\\Profiles'], ['Pale Moon/Profiles'], ['.moonchild productions/pale moon']),
    basilisk:  getMozProfileBases(['Moonchild Productions\\Basilisk\\Profiles'], ['Basilisk/Profiles'], ['.moonchild productions/basilisk']),
    iceweasel: getMozProfileBases(['Iceweasel\\Profiles'], ['Iceweasel/Profiles'], ['.iceweasel']),
  };
}

ipcMain.handle('setup:detect-browsers', () => {
  const home = os.homedir();
  const pl   = process.platform;
  const exists = p => { try { return !!p && fs.existsSync(p); } catch { return false; } };
  const chromiumPaths = _buildChromiumPaths();
  const mozBases      = _buildMozillaForkBases();

  const BROWSERS = [
    // ── Chromium family ──
    { id: 'chrome',    name: 'Google Chrome' },
    { id: 'edge',      name: 'Microsoft Edge' },
    { id: 'brave',     name: 'Brave' },
    { id: 'opera',     name: 'Opera' },
    { id: 'opera-gx',  name: 'Opera GX' },
    { id: 'vivaldi',   name: 'Vivaldi' },
    { id: 'arc',       name: 'Arc' },
    { id: 'thorium',   name: 'Thorium' },
    { id: 'chromium',  name: 'Chromium' },
    { id: 'yandex',    name: 'Yandex Browser' },
    // ── Firefox family (all use mozlz4 format) ──
    { id: 'firefox',   name: 'Firefox',   isFirefox: true },
    { id: 'librewolf', name: 'LibreWolf', isFirefox: true },
    { id: 'zen',       name: 'Zen Browser',isFirefox: true },
    { id: 'waterfox',  name: 'Waterfox',  isFirefox: true },
    { id: 'floorp',    name: 'Floorp',    isFirefox: true },
    { id: 'palemoon',  name: 'Pale Moon', isFirefox: true },
    { id: 'basilisk',  name: 'Basilisk',  isFirefox: true },
    // ── Other ──
    ...(pl === 'darwin' ? [{ id: 'safari', name: 'Safari' }] : []),
    ...(pl === 'win32'  ? [{ id: 'ie',     name: 'IE Favorites' }] : []),
  ];

  return BROWSERS
    .map(b => {
      let found = false;
      if (_CHROME_BROWSER_IDS.has(b.id)) {
        found = !!_findChromiumBookmarks(chromiumPaths[b.id]);
      } else if (_MOZ_BROWSER_IDS.has(b.id)) {
        found = !!findMozillaBookmarkBackup(mozBases[b.id] || []);
      } else if (b.id === 'safari') {
        found = exists(path.join(home, 'Library', 'Safari', 'Bookmarks.plist'));
      } else if (b.id === 'ie') {
        found = exists(path.join(home, 'Favorites'));
      }
      return { id: b.id, name: b.name, found, isFirefox: !!b.isFirefox };
    });
});

ipcMain.handle('browser:import-bookmarks', async (_, browserId) => {
  // Strict allowlist — prevent renderer from supplying an arbitrary browserId
  if (typeof browserId !== 'string' ||
      (!_MOZ_BROWSER_IDS.has(browserId) && !_CHROME_BROWSER_IDS.has(browserId) && !_SPECIAL_IDS.has(browserId))) {
    return { error: 'Unknown browser' };
  }

  const home = os.homedir();
  const pl   = process.platform;

  // ── Firefox family (all use mozlz4 bookmark backups) ─────────────────────
  if (_MOZ_BROWSER_IDS.has(browserId)) {
    try {
      const mozBases  = _buildMozillaForkBases();
      const bakPath   = findMozillaBookmarkBackup(mozBases[browserId] || []);
      if (!bakPath) return { error: `No ${browserId} bookmark backup found` };
      const buf  = fs.readFileSync(bakPath);
      const json = JSON.parse(decodeMozlz4(buf).toString('utf8'));
      const bms  = extractFirefoxBookmarks(json);
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Internet Explorer / Edge Legacy (Favorites folder) ──────────────────
  if (browserId === 'ie') {
    try {
      const favDir = path.join(home, 'Favorites');
      const bms = [];
      for (const fpath of walkDir(favDir)) {
        if (!fpath.toLowerCase().endsWith('.url')) continue;
        try {
          const txt = fs.readFileSync(fpath, 'utf8');
          const m = txt.match(/^\s*URL\s*=\s*(.+)/im);
          if (!m) continue;
          const url = m[1].trim();
          if (!/^https?:\/\//i.test(url)) continue;
          bms.push({ title: path.basename(fpath, '.url'), url });
        } catch {}
      }
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Safari (macOS only) ────────────────────────────────────────────────────
  if (browserId === 'safari') {
    try {
      if (pl !== 'darwin') return { error: 'Safari is only on macOS' };
      const plistPath = path.join(home, 'Library', 'Safari', 'Bookmarks.plist');
      const { execSync } = require('child_process');
      const jsonStr = execSync(`plutil -convert json -o - "${plistPath}"`).toString('utf8');
      const root    = JSON.parse(jsonStr);
      const bms     = [];
      function walkSafari(node) {
        if (!node) return;
        if (node.WebBookmarkType === 'WebBookmarkTypeLeaf' && node.URLString && node.URIDictionary?.title) {
          if (/^https?:\/\//i.test(node.URLString))
            bms.push({ title: node.URIDictionary.title, url: node.URLString });
        }
        const children = node.Children || node.WebBookmarkChildren;
        if (Array.isArray(children)) children.forEach(walkSafari);
      }
      walkSafari(root);
      return { bookmarks: bms, count: bms.length };
    } catch (e) { return { error: e.message }; }
  }

  // ── Chromium-based browsers ────────────────────────────────────────────────
  const defaultBmPath = _buildChromiumPaths()[browserId];
  const bmPath = _findChromiumBookmarks(defaultBmPath);
  if (!bmPath) return { error: `${browserId} not found or has no bookmarks file` };
  try {
    const raw = JSON.parse(fs.readFileSync(bmPath, 'utf8'));
    const bms = [];
    function extractChrome(node) {
      if (!node) return;
      if (node.type === 'url' && node.url && node.name && /^https?:\/\//i.test(node.url))
        bms.push({ title: node.name, url: node.url });
      if (Array.isArray(node.children)) node.children.forEach(extractChrome);
    }
    ['bookmark_bar', 'other', 'synced'].forEach(k => extractChrome((raw.roots || {})[k]));
    return { bookmarks: bms, count: bms.length };
  } catch (e) { return { error: e.message }; }
});

// ── IPC: History ──────────────────────────────────────────────────────────────
ipcMain.on('history:clear', () => {
  history = [];
  save(F.history, []);
  send('history:set', []);
});

// ── IPC: Downloads ────────────────────────────────────────────────────────────
ipcMain.on('downloads:clear', () => {
  downloads = downloads.filter(d => d.state === 'progressing');
  save(F.downloads, []);
  send('downloads:update', downloads);
});
ipcMain.on('downloads:open',   (_, p) => {
  // Validate: must be an absolute path to an existing file in a safe location.
  // Never open paths that start with ~, contain .. traversal, or point outside home/downloads.
  if (typeof p !== 'string') return;
  try {
    const resolved = path.resolve(p);
    const safe = [
      os.homedir(),
      app.getPath('downloads'),
      app.getPath('temp'),
    ].some(d => resolved.startsWith(path.resolve(d) + path.sep) || resolved === path.resolve(d));
    if (!safe || !fs.existsSync(resolved)) return;
    shell.openPath(resolved).catch(() => {});
  } catch {}
});
ipcMain.on('downloads:reveal', (_, p) => {
  if (typeof p !== 'string') return;
  try {
    const resolved = path.resolve(p);
    const safe = [
      os.homedir(),
      app.getPath('downloads'),
      app.getPath('temp'),
    ].some(d => resolved.startsWith(path.resolve(d) + path.sep) || resolved === path.resolve(d));
    if (!safe) return;
    shell.showItemInFolder(resolved);
  } catch {}
});

// ── IPC: Settings ─────────────────────────────────────────────────────────────
ipcMain.on('settings:reset', () => {
  settings = { ...DEF_SETTINGS };
  save(F.settings, settings);
  send('settings:set', settings);
  send('toast', 'Settings reset to defaults', 'teal');
});
ipcMain.on('settings:set', (_, patch) => {
  settings = { ...settings, ...patch };
  save(F.settings, settings);
  send('settings:set', settings);

  // Update chrome height for compact mode — keeps BrowserView flush with nav bar
  if ('compactMode' in patch) {
    CHROME_H = settings.compactMode ? 72 : 82;
    // Update bounds for ALL tabs so any tab switched to immediately has correct layout
    for (const t of tabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) {
        try { setBounds(t.bv); } catch {}
      }
    }
  }

  if ('spoofUserAgent' in patch && settings.spoofUserAgent) {
    const ua = SPOOF_UA;
    for (const t of tabMap.values()) t.bv?.webContents.setUserAgent(ua);
  }

  // Re-inject geo spoofer live when geo settings change
  if ('geoEnabled' in patch || 'geoRegion' in patch) {
    for (const t of tabMap.values()) {
      if (!t.bv || t.url === 'newtab' || t.bv.webContents.isDestroyed()) continue;
      if (settings.geoEnabled && settings.geoRegion && GEO_REGIONS[settings.geoRegion]) {
        const gr = GEO_REGIONS[settings.geoRegion];
        t.bv.webContents.executeJavaScript(buildGeoScript(gr.lat, gr.lon)).catch(() => {});
      }
    }
  }
});

// ── IPC: Zoom ─────────────────────────────────────────────────────────────────
ipcMain.on('zoom:in',    (_, id) => setZoom(id, z => Math.min(z + 0.1, 3)));
ipcMain.on('zoom:out',   (_, id) => setZoom(id, z => Math.max(z - 0.1, 0.3)));
ipcMain.on('zoom:reset', (_, id) => setZoom(id, ()  => 1));

// ── IPC: Find ─────────────────────────────────────────────────────────────────
ipcMain.on('find', (_, { id, text, forward }) => {
  const t = tabMap.get(id);
  if (!t || !text) return;
  t.bv.webContents.findInPage(text, { forward });
});
ipcMain.on('find:stop', (_, id) => {
  tabMap.get(id)?.bv.webContents.stopFindInPage('clearSelection');
});

// ── IPC: DevTools / print / view-source ──────────────────────────────────────
ipcMain.on('devtools',    (_, id) => tabMap.get(id)?.bv.webContents.toggleDevTools());
ipcMain.on('print',       (_, id) => tabMap.get(id)?.bv.webContents.print());
ipcMain.on('source:view', (_, id) => {
  const t = tabMap.get(id);
  if (t?.url && t.url !== 'newtab') createTab('view-source:' + t.url);
});

// ── IPC: Privacy / clear data ─────────────────────────────────────────────────
ipcMain.on('privacy:clear', async (_, opts = {}) => {
  const ses = session.fromPartition('persist:main');
  if (opts.cache)   await ses.clearCache();
  if (opts.cookies) {
    await ses.clearStorageData({
      storages: ['cookies','localstorage','indexdb','websql','filesystem','serviceworkers','cachestorage'],
    });
  }
  if (opts.history)   { history   = []; save(F.history,   []); send('history:set',      []); }
  if (opts.downloads) { downloads = []; save(F.downloads, []); send('downloads:update', []); }
});

// ── IPC: Whitelist ────────────────────────────────────────────────────────────
ipcMain.on('whitelist:add', (_, domain) => {
  const d = domain.toLowerCase()
    .replace(/^(https?:\/\/)?(www\.)?/, '')
    .replace(/\/.*$/, '')
    .trim();
  if (d && !userWhitelist.includes(d)) {
    userWhitelist.push(d);
    save(F.whitelist, userWhitelist);
    send('whitelist:set', userWhitelist);
  }
});
ipcMain.on('whitelist:remove', (_, domain) => {
  userWhitelist = userWhitelist.filter(d => d !== domain);
  save(F.whitelist, userWhitelist);
  send('whitelist:set', userWhitelist);
});

// ── IPC: Wallpaper picker ─────────────────────────────────────────────────────
ipcMain.on('wallpaper:pick', async () => {
  const r = await dialog.showOpenDialog(win, {
    properties: ['openFile'],
    filters: [{ name: 'Images', extensions: ['jpg','jpeg','png','gif','webp'] }],
  });
  if (!r.canceled && r.filePaths[0]) {
    // Store as a proper file:// URL so Chromium can use it directly in CSS url()
    settings.wallpaper = pathToFileURL(r.filePaths[0]).href;
    save(F.settings, settings);
    send('settings:set', settings);
  }
});

// ── IPC: Extensions ───────────────────────────────────────────────────────────
ipcMain.on('ext:toggle', (_, { id, enabled }) => {
  if (!settings.extensions) settings.extensions = {};
  settings.extensions[id] = !!enabled;
  save(F.settings, settings);
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') {
    const script = enabled ? EXT_SCRIPTS[id] : EXT_UNSCRIPTS[id];
    if (script) tab.bv.webContents.executeJavaScript(script).catch(() => {});
  }
});

// ── IPC: Incognito (Ignore) separate window ────────────────────────────
let incognitoWin  = null;
const igTabMap    = new Map();
let   igNextId    = 5000;
let   igActiveId  = null;

function sendIg(ch, ...a) {
  if (incognitoWin && !incognitoWin.isDestroyed()) incognitoWin.webContents.send(ch, ...a);
}

const IG_TOP = 82; // tab-row 34 + nav-row 48
const IG_SEARCH = 'https://www.startpage.com/search?q=';
function igResolveUrl(raw) {
  if (!raw || raw === 'newtab') return 'newtab';
  // Allow file:// URLs and bare paths pointing to local html/xhtml/pdf files
  if (/\.(html?|xhtml|pdf)$/i.test(raw) && !/^(javascript|vbscript|data):/i.test(raw)) return raw;
  if (/^(javascript|vbscript|data|file):/i.test(raw)) return IG_SEARCH + encodeURIComponent(raw);
  if (/^(https?|ftp):\/\//i.test(raw)) return raw;
  if (/^(about:|view-source:)/i.test(raw)) return raw;
  if (/^localhost(:\d+)?(\/.*)?$/.test(raw)) return 'http://' + raw;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(raw)) return 'https://' + raw;
  return IG_SEARCH + encodeURIComponent(raw);
}
function igSetBounds(bv) {
  if (!incognitoWin || incognitoWin.isDestroyed()) return;
  const [w, h] = incognitoWin.getContentSize();
  bv.setBounds({ x: 0, y: IG_TOP, width: w, height: Math.max(1, h - IG_TOP) });
}

function igNavData(tab) {
  if (!tab?.bv || tab.bv.webContents.isDestroyed()) return { url: tab?.url, canBack: false, canFwd: false };
  const wc = tab.bv.webContents;
  return { url: tab.url, title: tab.title, loading: tab.loading, canBack: wc.canGoBack(), canFwd: wc.canGoForward() };
}

function igActivateTab(id) {
  const tab = igTabMap.get(id);
  if (!tab || !incognitoWin || incognitoWin.isDestroyed()) return;
  for (const t of igTabMap.values()) { if (t.bv) try { incognitoWin.removeBrowserView(t.bv); } catch {} }
  if (tab.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) {
    incognitoWin.addBrowserView(tab.bv);
    igSetBounds(tab.bv);
  }
  igActiveId = id;
  sendIg('ig:tab:activate', id);
  sendIg('ig:nav:state', igNavData(tab));
}

function igCreateTab(url = 'newtab', activate = true) {
  const id = ++igNextId;
  const bv = new BrowserView({
    backgroundColor: '#0a071a',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          true,
      partition:        'incognito',
      preload:          path.join(__dirname, 'preload.js'),
      webSecurity:      true,
      experimentalFeatures: true,
    },
  });
  const tab = { id, bv, url: url === 'newtab' ? 'newtab' : url, title: 'New Tab', favicon: null, loading: false };
  igTabMap.set(id, tab);
  const wc = bv.webContents;
  wc.setBackgroundThrottling(false);
  wc.setUserAgent(SPOOF_UA);
  wc.setWindowOpenHandler(({ url: u }) => {
    if (/^(javascript|vbscript|file):/i.test(u)) return { action: 'deny' };
    igCreateTab(u, true); return { action: 'deny' };
  });
  // Inject Google UA fix on every page load in incognito (email → password → 2FA)
  wc.on('dom-ready', () => _injectGoogleUAFix(wc));
  const norm = u => (u && u !== 'about:blank') ? u : '';
  wc.on('page-title-updated', (_, t) => {
    tab.title = t;
    sendIg('ig:tab:update', { id, url: tab.url, title: t, loading: tab.loading, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
  });
  wc.on('did-start-loading', () => {
    tab.loading = true;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: true, favicon: tab.favicon });
  });
  wc.on('did-navigate', (_, u) => {
    tab.url = norm(u) || tab.url; tab.favicon = null;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: null });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    _injectGoogleUAFix(wc);
  });
  wc.on('did-navigate-in-page', (_, u) => {
    tab.url = norm(u) || tab.url;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    _injectGoogleUAFix(wc);
  });
  wc.on('page-favicon-updated', (_, favs) => {
    tab.favicon = favs[0] || null;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: tab.loading, favicon: tab.favicon });
  });
  wc.on('did-stop-loading', () => {
    tab.loading = false;
    tab.url = norm(wc.getURL()) || tab.url;
    sendIg('ig:tab:update', { id, url: tab.url, title: tab.title, loading: false, favicon: tab.favicon });
    if (igActiveId === id) sendIg('ig:nav:state', igNavData(tab));
    if (/youtube\.com/i.test(tab.url) && settings.extensions?.['yt-ad']) wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    wc.insertCSS('html::-webkit-scrollbar{display:none!important}html{scrollbar-width:none!important}', { cssOrigin:'user' }).catch(() => {});
    // Inject floating PiP button — same as main browser
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript('window._rawPipInjected=false;window._rawPipV3=false;').catch(()=>{});
      wc.executeJavaScript(VIDEO_PIP_INJECT).catch(() => {});
    }
  });
  sendIg('ig:tab:add', { id, url: tab.url, title: tab.title, loading: false, favicon: null });
  if (url !== 'newtab') {
    const resolved = igResolveUrl(url);
    tab.url = resolved; tab.loading = true;
    wc.loadURL(resolved).catch(() => {});
  }
  if (activate) igActivateTab(id);
  return tab;
}

ipcMain.on('incognito:open', () => {
  if (incognitoWin && !incognitoWin.isDestroyed()) { incognitoWin.focus(); return; }
  incognitoWin = new BrowserWindow({
    width: 1200, height: 800, minWidth: 640, minHeight: 400,
    frame: false, backgroundColor: '#0a071a',
    icon: path.join(__dirname, 'assets', process.platform === 'darwin' ? 'logo.icns' : 'logo.ico'),
    webPreferences: { nodeIntegration: true, contextIsolation: false, webviewTag: false },
  });
  igTabMap.clear(); igActiveId = null; igNextId = 5000;
  incognitoWin.loadFile(path.join(__dirname, 'incognito.html'));
  incognitoWin.once('ready-to-show', () => {
    incognitoWin.show();
    if (win && !win.isDestroyed()) win.webContents.send('incognito:state', true);
    // Send current theme/accent so incognito window can match
    sendIg('ig:settings', { theme: settings.theme || 'dark', accentColor: settings.accentColor });
    igCreateTab('newtab', true);
  });
  incognitoWin.on('resize', () => {
    for (const t of igTabMap.values()) {
      if (t.bv && t.url !== 'newtab' && !t.bv.webContents.isDestroyed()) try { igSetBounds(t.bv); } catch {}
    }
  });
  incognitoWin.on('closed', () => {
    for (const t of igTabMap.values()) { if (t.bv) try { t.bv.webContents.destroy(); } catch {} }
    igTabMap.clear(); igActiveId = null; incognitoWin = null;
    if (win && !win.isDestroyed()) win.webContents.send('incognito:state', false);
  });
});

ipcMain.on('ig:tab:create',   (_, url) => igCreateTab(url || 'newtab', true));
ipcMain.on('ig:tab:activate', (_, id)  => igActivateTab(id));
ipcMain.on('ig:tab:close',    (_, id)  => {
  const tab = igTabMap.get(id); if (!tab) return;
  if (tab.bv) { try { incognitoWin?.removeBrowserView(tab.bv); } catch {} try { tab.bv.webContents.destroy(); } catch {} }
  igTabMap.delete(id);
  if (igTabMap.size === 0) { if (incognitoWin && !incognitoWin.isDestroyed()) incognitoWin.close(); return; }
  if (igActiveId === id) { const next = [...igTabMap.values()].pop(); if (next) igActivateTab(next.id); }
  sendIg('ig:tab:remove', id);
});
ipcMain.on('ig:nav:go', (_, raw) => {
  const tab = igTabMap.get(igActiveId); if (!tab?.bv) return;
  const url = igResolveUrl(raw); tab.url = url; tab.loading = true;
  // Ensure BrowserView is visible (won't be attached if we were on newtab)
  if (incognitoWin && !incognitoWin.isDestroyed()) {
    try { incognitoWin.removeBrowserView(tab.bv); } catch {}
    incognitoWin.addBrowserView(tab.bv);
    igSetBounds(tab.bv);
  }
  tab.bv.webContents.loadURL(url).catch(() => {});
});
ipcMain.on('ig:nav:back',    () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.goBack(); });
ipcMain.on('ig:nav:forward', () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.goForward(); });
ipcMain.on('ig:nav:reload',  () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.reload(); });
ipcMain.on('ig:nav:stop',    () => { const t = igTabMap.get(igActiveId); if (t?.bv) t.bv.webContents.stop(); });
ipcMain.on('ig:win:minimize', () => { incognitoWin?.minimize(); });
ipcMain.on('ig:win:maximize', () => {
  if (!incognitoWin) return;
  incognitoWin.isMaximized() ? incognitoWin.unmaximize() : incognitoWin.maximize();
});
ipcMain.on('ig:win:close',   () => { incognitoWin?.close(); });
ipcMain.on('ig:win:moveBy',  (_, { dx, dy }) => {
  if (!incognitoWin || incognitoWin.isDestroyed()) return;
  const [x, y] = incognitoWin.getPosition();
  incognitoWin.setPosition(Math.round(x + dx), Math.round(y + dy));
});

ipcMain.on('ig:pip:start', () => {
  const tab = igTabMap.get(igActiveId);
  if (!tab?.bv) { sendIg('ig:toast', 'No active tab'); return; }
  tab.bv.webContents.executeJavaScript(`
    (function(){
      var v=document.querySelector('video');
      if(!v){return 'no-video';}
      if(document.pictureInPictureElement){document.exitPictureInPicture().catch(function(){});}
      else{v.requestPictureInPicture().catch(function(e){console.warn('[RAW Incognito] PiP:',e.message);});}
    })()
  `).catch(() => {});
});

// ── IPC: Main-browser PiP — same method as incognito, userGesture propagated from toolbar click ──
ipcMain.on('bv:pip:start', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) return;
  tab.bv.webContents.executeJavaScript(`
    (function(){
      // Best-video selection: prefer playing, largest on screen
      var vw=window.innerWidth, vh=window.innerHeight;
      var best=null, bestScore=-1;
      document.querySelectorAll('video').forEach(function(v){
        var r=v.getBoundingClientRect();
        if(r.width<80||r.height<50)return;
        if(r.right<0||r.bottom<0||r.left>vw||r.top>vh)return;
        var score=(!v.paused?3000:0)+(v.duration||0)*10+(r.width*r.height/1e4);
        if(score>bestScore){bestScore=score;best=v;}
      });
      // YouTube fallback
      if(!best) best=document.querySelector('#movie_player video,.html5-video-player video');
      // Generic fallback
      if(!best) best=document.querySelector('video');
      if(!best)return;
      try{best.disablePictureInPicture=false;}catch(e){}
      if(document.pictureInPictureElement){
        document.exitPictureInPicture().catch(function(){});
      } else {
        best.requestPictureInPicture().catch(function(e){
          console.warn('[RAW PiP]',e.message);
        });
      }
    })()
  `, true /* userGesture — propagated from toolbar button click via IPC */).catch(() => {});
});

// ── IPC: Autofill bridge ──────────────────────────────────────────────────────
ipcMain.on('autofill:query', (_, data) => {
  // Forward login-form detection from active tab to renderer (vault lookup)
  send('autofill:query', data);
});
ipcMain.on('autofill:fill', (_, data) => {
  // Forward fill credentials back to the active tab's preload
  const tab = tabMap.get(activeId);
  if (tab && tab.bv) tab.bv.webContents.send('autofill:fill', data);
});
ipcMain.on('autofill:save-prompt', (_, data) => {
  // Forward save-password prompt from active tab to renderer
  send('autofill:save-prompt', data);
});

// ── IPC: Picture-in-Picture ───────────────────────────────────────────────────
ipcMain.on('pip:start', () => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) { send('toast', 'No active tab', 'err'); return; }
  tab.bv.webContents.executeJavaScript(`
    (function(){
      var v=document.querySelector('video');
      if(!v){return 'no-video';}
      if(document.pictureInPictureElement){document.exitPictureInPicture().catch(function(){});}
      else{v.requestPictureInPicture().catch(function(e){console.warn('[RAW] PiP:',e.message);});}
    })()
  `).then(res => {
    if (res === 'no-video') send('toast', 'No video found on this page', 'err');
  }).catch(() => {});
});

// ── IPC: Translate ────────────────────────────────────────────────────────────
ipcMain.on('translate:page', (_, lang) => {
  const tab = tabMap.get(activeId);
  if (!tab || tab.url === 'newtab') return;
  const targetLang = lang || settings.translateLang || 'en';
  const url = `https://translate.google.com/translate?sl=auto&tl=${targetLang}&u=${encodeURIComponent(tab.url)}`;
  createTab(url, true);
});

// ── IPC: Misc ─────────────────────────────────────────────────────────────────
ipcMain.on('adblock:refresh', () => send('toast', 'Filter lists refreshed', 'teal'));
ipcMain.on('poison:signal',   () => {});

// Inject persona-appropriate cookies & localStorage into the active tab (safe — only affects current page domain)
ipcMain.on('poison:inject-cookies', (_e, { keyword, interests }) => {
  const tab = tabMap.get(activeId);
  if (!tab?.bv) return;
  const kw  = String(keyword  || '').replace(/[`\\]/g, '');
  const ints = (Array.isArray(interests) ? interests : []).map(s => String(s).replace(/[`\\]/g, '')).slice(0, 20);
  // Inject safely — only sets cookies/localStorage for the current page's own domain
  tab.bv.webContents.executeJavaScript(`
    (function(kw, ints) {
      try {
        localStorage.setItem('_raw_persona',     kw);
        localStorage.setItem('_raw_interests',   ints.join(','));
        localStorage.setItem('_ga_audience_seg', kw);
        localStorage.setItem('_fbp_interests',   ints.join('|'));
      } catch {}
      try {
        const d = new Date(); d.setFullYear(d.getFullYear() + 1);
        const exp = '; path=/; expires=' + d.toUTCString();
        document.cookie = '_persona='          + encodeURIComponent(kw)             + exp;
        document.cookie = 'audience_segment='  + ints.map(encodeURIComponent).join(',') + exp;
        document.cookie = 'interest_category=' + encodeURIComponent(ints[0] || kw)  + exp;
      } catch {}
    })(${JSON.stringify(kw)}, ${JSON.stringify(ints)})
  `).catch(() => {});
});

// ── yt-dlp integration ────────────────────────────────────────────────────────
const YTDLP_REPO   = 'yt-dlp/yt-dlp';
const YTDLP_GH_API = 'https://api.github.com/repos/' + YTDLP_REPO + '/releases/latest';

function ytdlpBinName() {
  if (process.platform === 'win32') return 'yt-dlp.exe';
  if (process.platform === 'darwin') return 'yt-dlp_macos';
  return 'yt-dlp';
}

function ytdlpBinPath() {
  return path.join(app.getPath('userData'), 'rawbrowser', ytdlpBinName());
}

function ytdlpVersionFile() {
  return path.join(app.getPath('userData'), 'rawbrowser', 'yt-dlp-version.txt');
}

function ytdlpReadLocalVersion() {
  try { return fs.readFileSync(ytdlpVersionFile(), 'utf8').trim(); } catch { return null; }
}

function ytdlpSaveLocalVersion(v) {
  try { fs.writeFileSync(ytdlpVersionFile(), v); } catch {}
}

function httpsGet(url) {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const req = https.get({
      hostname: opts.hostname, path: opts.pathname + opts.search,
      headers: { 'User-Agent': 'RawBrowser/1.0', 'Accept': 'application/vnd.github+json' },
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return httpsGet(res.headers.location).then(resolve).catch(reject);
      }
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpsDownload(url, destPath) {
  return new Promise((resolve, reject) => {
    function follow(u) {
      const opts = new URL(u);
      https.get({
        hostname: opts.hostname, path: opts.pathname + opts.search,
        headers: { 'User-Agent': 'RawBrowser/1.0' },
      }, res => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
        const out = fs.createWriteStream(destPath);
        res.pipe(out);
        out.on('finish', () => { out.close(); resolve(); });
        out.on('error', reject);
      }).on('error', reject);
    }
    follow(url);
  });
}

async function ytdlpFetchLatest() {
  const { body } = await httpsGet(YTDLP_GH_API);
  const data = JSON.parse(body);
  const version = data.tag_name;
  const assetName = ytdlpBinName();
  const asset = (data.assets || []).find(a => a.name === assetName);
  if (!asset) throw new Error('No binary for this platform in latest release');
  return { version, downloadUrl: asset.browser_download_url };
}

async function ytdlpInstallOrUpdate(forceUpdate = false) {
  send('ytdlp:installing', forceUpdate ? 'Updating yt-dlp…' : 'Downloading yt-dlp…');
  try {
    const { version, downloadUrl } = await ytdlpFetchLatest();
    await httpsDownload(downloadUrl, ytdlpBinPath());
    // Make executable on unix
    if (process.platform !== 'win32') {
      try { fs.chmodSync(ytdlpBinPath(), 0o755); } catch {}
    }
    ytdlpSaveLocalVersion(version);
    send('ytdlp:status', { ready: true, version, updateAvailable: false });
  } catch (err) {
    send('ytdlp:status', { ready: false, error: 'Install failed: ' + err.message });
  }
}

async function ytdlpCheckUpdate() {
  const binExists = fs.existsSync(ytdlpBinPath());
  if (!binExists) {
    send('ytdlp:status', { ready: false, version: null, updateAvailable: true });
    return;
  }
  try {
    const local = ytdlpReadLocalVersion();
    const { version: latest } = await ytdlpFetchLatest();
    const updateAvailable = local !== latest;
    send('ytdlp:status', {
      ready: true, version: local || 'unknown',
      updateAvailable, latestVersion: latest,
    });
  } catch {
    // Network error — still mark as ready if binary exists
    const local = ytdlpReadLocalVersion();
    send('ytdlp:status', { ready: true, version: local || 'unknown', updateAvailable: false });
  }
}

// Active yt-dlp child processes keyed by job ID
const ytdlpProcs = new Map();

ipcMain.on('ytdlp:check-update', () => ytdlpCheckUpdate());
ipcMain.on('ytdlp:update',       () => ytdlpInstallOrUpdate(true));

ipcMain.handle('ytdlp:pick-outdir', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.on('ytdlp:download', (_, { id, url, mode, quality, audiofmt, videofmt, outdir }) => {
  const bin = ytdlpBinPath();
  if (!fs.existsSync(bin)) {
    send('ytdlp:error', { id, error: 'yt-dlp not installed' });
    ytdlpInstallOrUpdate(false);
    return;
  }

  const outDir  = outdir || app.getPath('downloads');
  const outTmpl = path.join(outDir, '%(title)s.%(ext)s');
  let args;
  const baseArgs = ['--no-check-certificate', '--no-playlist', '--newline', '--progress', '-o', outTmpl];
  if (mode === 'audio') {
    const fmt = audiofmt || 'mp3';
    if (fmt === 'mp3' || fmt === 'wav') {
      // These require ffmpeg for conversion
      args = [url, '-x', '--audio-format', fmt, '--audio-quality', '0', ...baseArgs];
    } else {
      // m4a and opus can often be downloaded natively (no ffmpeg needed)
      const nativeFmt = fmt === 'm4a' ? 'bestaudio[ext=m4a]/bestaudio' : 'bestaudio[ext=webm]/bestaudio';
      args = [url, '-f', nativeFmt, '-x', '--audio-format', fmt, '--audio-quality', '0', ...baseArgs];
    }
  } else {
    const fmtStr = quality || 'bestvideo+bestaudio/best';
    const ext    = videofmt || 'mp4';
    args = [url, '-f', fmtStr, '--merge-output-format', ext, ...baseArgs];
  }

  let outPath = '';
  let title   = '';

  const proc = spawn(bin, args, { windowsHide: true });
  ytdlpProcs.set(id, proc);

  let lastErrLine = '';

  const lineBuffer = (stream, isStderr) => {
    let buf = '';
    stream.on('data', chunk => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;

        // Track last stderr line for error reporting
        if (isStderr && line && !line.startsWith('[download]')) lastErrLine = line;

        // Extract download destination (video file, before conversion)
        const titleM = line.match(/\[download\] Destination: (.+)/);
        if (titleM) {
          outPath = titleM[1].trim();
          title   = path.basename(outPath, path.extname(outPath));
        }

        // Extract audio conversion destination (final file after -x)
        const audioM = line.match(/\[ExtractAudio\] Destination: (.+)/);
        if (audioM) {
          outPath = audioM[1].trim();
          title   = path.basename(outPath, path.extname(outPath));
          // Emit 100% progress for extraction phase
          send('ytdlp:progress', { id, percent: 99, speed: '', status: 'Converting…', title, outPath });
          continue;
        }

        // [Merger] or [MoveFiles] — final step for video merge
        const mergeM = line.match(/\[Merger\] Merging formats into "(.+)"/);
        if (mergeM) { outPath = mergeM[1].trim(); title = path.basename(outPath, path.extname(outPath)); }

        // Parse progress: [download]  42.3% of ~  10.00MiB at  1.23MiB/s ETA 00:04
        const prgM = line.match(/\[download\]\s+([\d.]+)%.*?at\s+([\d.]+\S+)\s+ETA\s+(\S+)/);
        if (prgM) {
          send('ytdlp:progress', {
            id,
            percent: parseFloat(prgM[1]),
            speed:   prgM[2] + '/s',
            status:  'ETA ' + prgM[3],
            title,
            outPath,
          });
          continue;
        }

        // Fallback: any [download] line with %
        const pctM = line.match(/\[download\]\s+([\d.]+)%/);
        if (pctM) {
          send('ytdlp:progress', { id, percent: parseFloat(pctM[1]), speed: '', status: pctM[1]+'%', title, outPath });
        }
      }
    });
  };

  lineBuffer(proc.stdout, false);
  lineBuffer(proc.stderr, true);

  proc.on('close', code => {
    ytdlpProcs.delete(id);
    if (code === 0) {
      send('ytdlp:done', { id, outPath, title });
    } else if (code !== null) {
      // killed = code null
      const errMsg = lastErrLine || ('Process exited with code ' + code);
      send('ytdlp:error', { id, error: errMsg });
    }
  });
  proc.on('error', err => {
    ytdlpProcs.delete(id);
    send('ytdlp:error', { id, error: err.message });
  });
});

ipcMain.on('ytdlp:cancel', (_, id) => {
  const proc = ytdlpProcs.get(id);
  if (proc) { proc.kill(); ytdlpProcs.delete(id); }
});

// ── Auto update checker ───────────────────────────────────────────────────────
const CURRENT_VERSION = '1.0.4';
ipcMain.handle('check-update', () => new Promise((resolve) => {
  const url = 'https://raw.githubusercontent.com/sharp4real/rawbrowser/refs/heads/main/version';
  const req = https.get(url, { timeout: 8000, headers: { 'User-Agent': SPOOF_UA } }, (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
      const match = data.match(/version=([^\s\n\r]+)/);
      const remote = match ? match[1].trim() : null;
      resolve({ remote, current: CURRENT_VERSION, outdated: remote !== null && remote !== CURRENT_VERSION });
    });
  });
  req.on('error', () => resolve({ remote: null, current: CURRENT_VERSION, outdated: false }));
  req.on('timeout', () => { req.destroy(); resolve({ remote: null, current: CURRENT_VERSION, outdated: false }); });
}));