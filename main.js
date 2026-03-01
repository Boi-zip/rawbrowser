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
const { shouldBlock }    = require('./blocklist.js');

// Domains never blocked regardless of settings (needed for site functionality)
const BUILTIN_WHITELIST = [
  'tiktok.com','tiktokv.com','tiktokcdn.com','tiktokcdn-us.com',
  'ttwstatic.com','byteoversea.com','ibytedtos.com','ibyteimg.com',
  'musical.ly','snssdk.com','bdurl.net',
  // Spotify — CDN, auth, and DRM license domains required for playback
  'spotify.com','scdn.co','spotifycdn.com','spotifycdn.net',
  'pscdn.co','spotilocal.com','audio-ak-spotify-com.akamaized.net',
];

if (process.platform === 'win32') app.setAppUserModelId('com.raw.browser');

// ── ENHANCED PRIVACY: Prevent IP leaks through WebRTC ───────────────────────
app.commandLine.appendSwitch('disable-webrtc-ip-handling');
app.commandLine.appendSwitch('disable-features', 'WebRtcHideLocalIpsWithMdns');
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

  try {
    if (process.platform === 'win32') {
      const local = process.env.LOCALAPPDATA || '';
      const prog  = process.env.PROGRAMFILES || 'C:\\Program Files';
      const prog86 = process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)';
      // Try Chrome first (user install), then Edge (built-in on Windows 10/11), then system Chrome
      const candidates = [
        path.join(local,  'Google', 'Chrome', 'Application'),
        path.join(local,  'Microsoft', 'Edge', 'Application'),
        path.join(prog,   'Google', 'Chrome', 'Application'),
        path.join(prog86, 'Google', 'Chrome', 'Application'),
        path.join(prog,   'Microsoft', 'Edge', 'Application'),
      ];
      for (const c of candidates) { if (_tryDir(c)) break; }
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

const SPOOF_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// ── YouTube stealth ad-skip content script ────────────────────────────────────
// Stealth design:
//  • Random variable key per-injection — can't be fingerprinted by name
//  • No setInterval — purely event-driven (MutationObserver + rAF)
//  • Fast-forward at 16× instead of seeking to end — ad impression fires,
//    but the user sees <1 s of content; far less detectable than timeUpdate jump
//  • CSS hides banner/in-feed/overlay ad units silently — no DOM removal
//  • One-shot 900ms delayed check handles late-loading ads, not a recurring poll
const YT_AD_SKIP = `(function(){
  // Rotating key — prevents fingerprint detection via window property scan
  var _k='_rb'+Math.random().toString(36).slice(2,7);
  if(window[_k]){try{window[_k].disconnect();}catch(e){}delete window[_k];}

  // One-time CSS injection to hide non-video ad units invisibly
  if(!document.getElementById('_rb_ac')){
    var _s=document.createElement('style');
    _s.id='_rb_ac';
    _s.textContent=
      'ytd-promoted-sparkles-text-search-renderer,ytd-promoted-video-renderer,'+
      'ytd-display-ad-renderer,ytd-banner-promo-renderer,#masthead-ad,'+
      'ytd-ad-slot-renderer,ytd-in-feed-ad-layout-renderer,'+
      'ytd-action-companion-ad-renderer,.ytd-merch-shelf-renderer,'+
      '#player-ads>.ytd-watch-flexy,.ytp-ad-overlay-container,'+
      '[id^="google_ads_iframe"],[id^="aswift_"]{display:none!important}'+
      '.ad-showing .ytp-pause-overlay{display:none!important}';
    (document.head||document.documentElement).appendChild(_s);
  }

  function _act(){
    try{
      var player=document.querySelector('#movie_player,.html5-video-player');
      var video=document.querySelector('video.html5-main-video,video');
      var inAd=player&&(player.classList.contains('ad-showing')||player.classList.contains('ad-interrupting'));

      if(inAd&&video&&video.readyState>0){
        // Mute + fast-forward: ad still "plays" so impression signals fire,
        // but user experience is instant. Much stealthier than currentTime jump.
        if(!video.muted)video.muted=true;
        if(video.playbackRate<8)video.playbackRate=16;
      } else if(video&&!inAd){
        // Restore normal playback as soon as ad ends
        if(video.playbackRate!==1)video.playbackRate=1;
        if(video.muted)video.muted=false;
      }

      // Click skip button if it became visible
      var skip=document.querySelector(
        '.ytp-skip-ad-button:not([style*="display: none"]),.ytp-ad-skip-button-modern,.ytp-ad-skip-button-slot .ytp-button'
      );
      if(skip&&skip.offsetParent!==null){skip.click();}

      // Dismiss overlay close buttons
      document.querySelectorAll(
        '.ytp-ad-overlay-close-button,.ytp-ad-overlay-slot-close-button,.ytp-suggested-action-badge-expanded-close-button'
      ).forEach(function(el){try{el.click();}catch(e){}});
    }catch(e){}
  }

  // Observer — react only to ad-relevant mutations
  var _obs=new MutationObserver(function(muts){
    for(var i=0;i<muts.length;i++){
      var t=muts[i].target;
      if(t&&t.classList&&(
        t.classList.contains('ad-showing')||
        t.classList.contains('ad-interrupting')||
        t.classList.contains('ytp-ad-player-overlay')
      )){requestAnimationFrame(_act);return;}
      if(muts[i].addedNodes&&muts[i].addedNodes.length){
        requestAnimationFrame(_act);return;
      }
    }
  });
  window[_k]=_obs;

  function _attach(){
    var p=document.querySelector('#movie_player,.html5-video-player,ytd-player');
    if(p){
      _obs.observe(p,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});
    } else {
      // Player not in DOM yet — wait shallowly at root level
      var _w=new MutationObserver(function(){
        var p2=document.querySelector('#movie_player,.html5-video-player,ytd-player');
        if(p2){_w.disconnect();_obs.observe(p2,{childList:true,subtree:true,attributes:true,attributeFilter:['class']});}
      });
      _w.observe(document.documentElement,{childList:true,subtree:false});
    }
  }
  _attach();
  requestAnimationFrame(_act);
  // One-shot delayed check — catches ads that load after initial paint
  setTimeout(function(){requestAnimationFrame(_act);},900);
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
  /imasdk\.googleapis\.com/i,          // Google IMA SDK — video ad loader
  /googleadservices\.com/i,
  /googlesyndication\.com/i,
  /youtube\.com\/pagead\/paralleladview/i,
  /youtube\.com\/api\/stats\/qoe\?.*adformat/i, // QoE only when ad-related
];

// ── Video PiP floating button — injected into every BV page ──────────────────
// A click inside the page gives requestPictureInPicture() a real user gesture.
const VIDEO_PIP_INJECT = `(function(){
  if(window._rawPipInjected)return;
  window._rawPipInjected=true;

  // Single shared floating button — position:fixed
  var btn=document.createElement('button');
  btn.textContent='\u29c9 Pop Out';
  btn.style.cssText='position:fixed;z-index:2147483647;top:-100px;right:12px;'+
    'background:rgba(0,0,0,.88);color:#fff;border:1px solid rgba(255,255,255,.25);'+
    'border-radius:8px;padding:7px 16px;font:600 12px/1 -apple-system,sans-serif;'+
    'cursor:pointer;opacity:0;transition:opacity .2s;pointer-events:all;'+
    'backdrop-filter:blur(10px);white-space:nowrap;box-shadow:0 2px 14px rgba(0,0,0,.6);';
  document.documentElement.appendChild(btn);

  var currentVideo=null,hideTimer=null,mx=0,my=0;

  function positionBtn(r){
    btn.style.top=(r.top+12)+'px';
    btn.style.right=(window.innerWidth-r.right+12)+'px';
  }
  function showBtn(v,r){
    clearTimeout(hideTimer);
    currentVideo=v;
    positionBtn(r);
    btn.style.opacity='1';
  }
  function scheduleHide(){
    hideTimer=setTimeout(function(){btn.style.opacity='0';currentVideo=null;},400);
  }

  btn.addEventListener('mouseenter',function(){clearTimeout(hideTimer);});
  btn.addEventListener('mouseleave',scheduleHide);
  btn.addEventListener('click',function(e){
    e.stopPropagation();e.preventDefault();
    var v=currentVideo;if(!v)return;
    try{
      if(document.pictureInPictureElement){document.exitPictureInPicture().catch(function(){});}
      else{v.requestPictureInPicture().catch(function(err){console.warn('[RAW PiP]',err.message);});}
    }catch(ex){}
  });

  /* Use mousemove on document — works even when overlay divs cover the video.
     Check every known video rect on each move (cheap: videos are few). */
  document.addEventListener('mousemove',function(e){
    mx=e.clientX;my=e.clientY;
    var videos=document.querySelectorAll('video');
    var found=null,foundR=null;
    for(var i=0;i<videos.length;i++){
      var v=videos[i];
      if(v.readyState<1||v.videoWidth<10)continue; // ignore audio-only/hidden
      var r=v.getBoundingClientRect();
      if(r.width<80||r.height<50)continue;
      if(mx>=r.left&&mx<=r.right&&my>=r.top&&my<=r.bottom){found=v;foundR=r;break;}
    }
    if(found){
      showBtn(found,foundR);
    }else if(currentVideo){
      // If mouse left video area (but not onto btn), schedule hide
      var br=btn.getBoundingClientRect();
      var onBtn=mx>=br.left&&mx<=br.right&&my>=br.top&&my<=br.bottom;
      if(!onBtn) scheduleHide();
    }
  },{passive:true});

  /* Also watch for new videos added dynamically */
  new MutationObserver(function(){}).observe(document.documentElement,{childList:true,subtree:true});
})();`;

// ── Extension content scripts (injected into BrowserView via executeJavaScript) ─
const EXT_SCRIPTS = {
  'dark-mode':
    `(function(){
      if(document.getElementById('_rawDark'))return;
      /* 1. Force color-scheme:dark so CSS media queries inside sites activate */
      var s=document.createElement('style');s.id='_rawDark';
      s.textContent=':root{color-scheme:dark!important;}'+
        '::selection{background:rgba(0,180,160,.5)!important;}';
      document.head.appendChild(s);
      /* 2. Patch matchMedia so prefers-color-scheme:dark returns true */
      try{
        var _omm=window.matchMedia.bind(window);
        window.matchMedia=function(q){
          if(q&&q.indexOf('prefers-color-scheme')!==-1){
            var dark=q.indexOf('dark')!==-1;
            return{matches:dark,media:q,onchange:null,
              addListener:function(){},removeListener:function(){},
              addEventListener:function(){},removeEventListener:function(){},
              dispatchEvent:function(){return false;}};
          }
          return _omm(q);
        };
      }catch(e){}
      /* 3. After page paints, check if it's still light — only then invert */
      function _applyInvert(){
        if(document.getElementById('_rawDarkInv'))return;
        var el=document.body||document.documentElement;
        var bg=getComputedStyle(el).backgroundColor;
        var m=bg.match(/\\d+/g);
        var lum=m?(+m[0]*299+(+m[1])*587+(+m[2])*114)/1000:255;
        if(lum>140){
          var si=document.createElement('style');si.id='_rawDarkInv';
          si.textContent='html{filter:invert(1) hue-rotate(180deg)!important;}'+
            'img,video,canvas,picture,svg,embed,object,iframe'+
            '{filter:invert(1) hue-rotate(180deg)!important;}';
          document.head.appendChild(si);
        }
      }
      if(document.readyState==='complete'){_applyInvert();}
      else{window.addEventListener('load',function(){setTimeout(_applyInvert,200);});}
      setTimeout(_applyInvert,400);
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
  'remove-banners':
    `(function(){if(document.getElementById('_rawBan'))return;var s=document.createElement('style');s.id='_rawBan';` +
    `s.textContent='[id*="cookie" i],[class*="cookie" i],[id*="gdpr" i],[class*="gdpr" i],[id*="consent" i],[class*="consent" i],[id*="onetrust"],[id*="cookiebot"],[class*="cc-window"],[class*="cookie-notice"],[class*="cookie-banner"],[class*="cookie-bar"],[data-nosnippet*="cookie"]{display:none!important;}body,html{overflow:auto!important;}';` +
    `document.head.appendChild(s);})()`,
  'highlight-links':
    `(function(){if(document.getElementById('_rawLinks'))return;var s=document.createElement('style');s.id='_rawLinks';s.textContent='a{text-decoration-line:underline!important;text-decoration-color:rgba(0,212,200,.55)!important;text-underline-offset:2px!important;}';document.head.appendChild(s);})()`,
  'scroll-progress':
    `(function(){if(document.getElementById('_rawScProg'))return;var b=document.createElement('div');b.id='_rawScProg';b.style.cssText='position:fixed;top:0;left:0;height:3px;width:0%;background:linear-gradient(90deg,#00d4c8,#00bdb0);z-index:2147483646;transition:width .08s linear;pointer-events:none';document.documentElement.appendChild(b);function _upd(){var s=document.documentElement;var p=s.scrollTop/(s.scrollHeight-s.clientHeight)*100;b.style.width=Math.min(100,isNaN(p)?0:p)+'%';}window.addEventListener('scroll',_upd,{passive:true});})()`,
  'font-boost':
    `(function(){if(document.getElementById('_rawFont'))return;var s=document.createElement('style');s.id='_rawFont';s.textContent='body,p,li,td,th,article,section,main{font-size:108%!important;line-height:1.75!important;}';document.head.appendChild(s);})()`,
  'reader-mode':
    `(function(){if(document.getElementById('_rawReader'))return;var s=document.createElement('style');s.id='_rawReader';s.textContent='body{max-width:720px!important;margin:32px auto!important;padding:0 24px!important;font-size:18px!important;line-height:1.85!important;background:#0c0c0c!important;color:#d8d8d8!important;}h1,h2,h3{color:#fff!important;}a{color:#00d4c8!important;}img{max-width:100%!important;height:auto!important;border-radius:6px;}nav,header,footer,aside,[class*="sidebar"],[id*="sidebar"],[class*="nav"],[id*="nav"],[class*="header"],[class*="footer"],[class*="related"],[class*="recommend"],[class*="ad-"],[id*="-ad"]{display:none!important;}';document.head.appendChild(s);})()`,
  'image-zoom':
    `(function(){if(window._rawImgZoom)return;window._rawImgZoom=true;var ov=document.createElement('div');ov.id='_rawImgZoomOv';ov.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:2147483647;display:none;align-items:center;justify-content:center;cursor:zoom-out;backdrop-filter:blur(6px)';var im=document.createElement('img');im.style.cssText='max-width:92vw;max-height:92vh;border-radius:6px;box-shadow:0 4px 60px rgba(0,0,0,.9)';ov.appendChild(im);document.documentElement.appendChild(ov);ov.addEventListener('click',function(){ov.style.display='none';});document.addEventListener('click',function(e){if(e.target.tagName==='IMG'&&e.target.naturalWidth>200){im.src=e.target.src;ov.style.display='flex';}});})()`,
  'word-count':
    `(function(){if(document.getElementById('_rawWordCnt'))return;var w=(document.body.innerText||'').trim().split(/\s+/).filter(Boolean).length;var m=Math.max(1,Math.round(w/200));var b=document.createElement('div');b.id='_rawWordCnt';b.style.cssText='position:fixed;bottom:18px;right:18px;background:rgba(10,10,10,.82);color:#aaa;font-size:11.5px;padding:5px 12px;border-radius:20px;z-index:2147483646;pointer-events:none;backdrop-filter:blur(10px);font-family:system-ui,sans-serif;letter-spacing:.02em;border:1px solid rgba(255,255,255,.08)';b.textContent=w.toLocaleString()+' words · '+m+' min read';document.documentElement.appendChild(b);})()`,
  'anti-tracking':
    `(function(){if(document.getElementById('_rawAntiTrk'))return;var s=document.createElement('style');s.id='_rawAntiTrk';s.textContent='img[width="1"],img[height="1"],img[width="0"],img[height="0"],img[style*="display:none"],img[style*="display: none"]{display:none!important;visibility:hidden!important;}';document.head.appendChild(s);})()`,
  'print-clean':
    `(function(){if(document.getElementById('_rawPrint'))return;var s=document.createElement('style');s.id='_rawPrint';s.textContent='@media print{nav,header,footer,aside,iframe,[class*="ad"],[id*="ad"],[class*="banner"],[class*="sidebar"],[class*="popup"],[class*="cookie"],[class*="social"],[class*="share"],[class*="related"]{display:none!important}body{font-size:11pt!important;line-height:1.6!important;color:#000!important;background:#fff!important}a::after{content:" ("attr(href)")";}img{max-width:100%!important}}';document.head.appendChild(s);})()`,
};

const EXT_UNSCRIPTS = {
  'dark-mode':       `(function(){['_rawDark','_rawDarkInv'].forEach(function(id){var e=document.getElementById(id);if(e)e.remove();});})()`,
  'no-animations':   `(function(){var s=document.getElementById('_rawNoAnim');if(s)s.remove();})()`,
  'video-speed':     `(function(){var el=document.getElementById('_rawSpeed');if(el)el.remove();delete window._rawSpeedUI;})()`,
  'focus-mode':      `(function(){var s=document.getElementById('_rawFocus');if(s)s.remove();})()`,
  'grayscale':       `(function(){var s=document.getElementById('_rawGray');if(s)s.remove();})()`,
  'night-filter':    `(function(){var el=document.getElementById('_rawNight');if(el)el.remove();})()`,
  'remove-banners':  `(function(){var s=document.getElementById('_rawBan');if(s)s.remove();})()`,
  'highlight-links':  `(function(){var s=document.getElementById('_rawLinks');if(s)s.remove();})()`,
  'scroll-progress':  `(function(){document.getElementById('_rawScProg')?.remove();})()`,
  'font-boost':       `(function(){document.getElementById('_rawFont')?.remove();})()`,
  'reader-mode':      `(function(){document.getElementById('_rawReader')?.remove();})()`,
  'image-zoom':       `(function(){document.getElementById('_rawImgZoomOv')?.remove();window._rawImgZoom=false;})()`,
  'word-count':       `(function(){document.getElementById('_rawWordCnt')?.remove();})()`,
  'anti-tracking':    `(function(){document.getElementById('_rawAntiTrk')?.remove();})()`,
  'print-clean':      `(function(){document.getElementById('_rawPrint')?.remove();})()`,
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
const CHROME_H   = 76;   // must match --chrome-h in index.html CSS
const SIDEBAR_W  = 64;   // sidebar strip width
let   sidebarOn  = false;
let   nextId     = 0;
const tabMap   = new Map();
let   activeId = null;
let   win      = null;
let   totalBlocked = 0;
let   panelOpen    = false;
let   panelClipX   = 0;       // >0 = BV clipped to leave room for open panel

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
    .map(t => ({ id: t.id, title: t.title, favicon: t.favicon, isAudible: t.isAudible, muted: t.muted }));
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

// ── URL helpers ───────────────────────────────────────────────────────────────
function normalizeUrl(raw) {
  if (!raw || raw === 'about:blank') return 'newtab';
  if (raw.includes('newtab.html'))   return 'newtab';
  return raw;
}

function resolveUrl(raw) {
  if (!raw || raw === 'newtab')                   return 'newtab';
  if (/^(https?|ftp|file):\/\//i.test(raw))       return raw;
  if (/^(about:|view-source:)/i.test(raw))         return raw;
  if (/^localhost(:\d+)?(\/.*)?$/.test(raw))       return 'http://' + raw;
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(raw))     return 'https://' + raw;
  const engine = settings.searchEngine || 'https://duckduckgo.com/?q=';
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
  
  // Remove all BrowserViews first
  for (const t of tabMap.values()) {
    if (t.bv) try { win.removeBrowserView(t.bv); } catch {}
  }
  
  // Only attach BrowserView for real pages — newtab is handled by HTML newtab-layer
  if (tab.bv && !panelOpen && tab.url !== 'newtab') {
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
    backgroundColor: '#ffffff',
    webPreferences: {
      nodeIntegration:  false,
      contextIsolation: true,
      sandbox:          false,
      partition:        'persist:main',
      preload:          path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });

  const tab = {
    id, bv,
    url: 'newtab', title: 'New Tab', favicon: null,
    loading: false, pinned: false, muted: false, zoom: 1, blocked: 0,
  };
  tabMap.set(id, tab);

  const wc = bv.webContents;
  if (settings.spoofUserAgent) wc.setUserAgent(SPOOF_UA);

  wc.setWindowOpenHandler(({ url: u }) => {
    // Block dangerous schemes from being opened as new tabs
    if (/^(javascript|vbscript|file):/i.test(u)) return { action: 'deny' };
    createTab(u, true);
    return { action: 'deny' };
  });

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
    tab.snapshot = null;
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
    // Inject YouTube ad skipper
    if (/youtube\.com/i.test(tab.url) && settings.adblockEnabled !== false) {
      wc.executeJavaScript(YT_AD_SKIP).catch(() => {});
    }
    // Inject floating PiP button for any page that might have video
    if (tab.url && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      wc.executeJavaScript(VIDEO_PIP_INJECT).catch(() => {});
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
    // Background snapshot — taken 1.2s after load for instant panel opens
    if (id === activeId && tab.url !== 'newtab' && !tab.url.startsWith('view-source:')) {
      setTimeout(() => {
        if (activeId === id && !panelOpen && tab?.bv && !tab.bv.webContents.isDestroyed()) {
          tab.bv.webContents.capturePage().then(img => {
            tab.snapshot = img.toDataURL();
          }).catch(() => {});
        }
      }, 1200);
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
    if (id === activeId) send('nav:state', navData(tab));
  });

  wc.on('did-navigate-in-page', (_, u) => {
    tab.url = normalizeUrl(u);
    send('tab:update', tabData(tab));
    if (id === activeId) send('nav:state', navData(tab));
    // Re-inject ad skipper on YouTube SPA navigation (video-to-video)
    if (/youtube\.com/i.test(u) && settings.adblockEnabled !== false) {
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
    if (settings.doNotTrack)    { h['DNT'] = '1'; h['Sec-GPC'] = '1'; }
    if (settings.spoofUserAgent) { h['User-Agent'] = SPOOF_UA; }

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

  // Deny tracking-risk permissions; allow safe ones
  const _deniedPerms = new Set(['geolocation', 'notifications', 'sensors', 'background-sync', 'payment-handler', 'idle-detection', 'periodic-background-sync', 'nfc', 'bluetooth']);
  ses.setPermissionRequestHandler((_, permission, callback) => {
    // When geo spoofing is enabled, allow geolocation — our JS serves fake coords
    if (permission === 'geolocation' && settings.geoEnabled) { callback(true); return; }
    callback(!_deniedPerms.has(permission));
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
    win.show();
    createTab('newtab', true);
    // Auto-check yt-dlp after UI is stable
    setTimeout(() => ytdlpCheckUpdate(), 3500);
  });

  win.on('resize', () => {
    const tab = tabMap.get(activeId);
    if (tab?.bv && !panelOpen && tab.url !== 'newtab') setBounds(tab.bv);
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
ipcMain.on('tab:new',       (_, url) => createTab(url || 'newtab'));
ipcMain.on('tab:switch',    (_, id)  => activateTab(id));
ipcMain.on('tab:close',     (_, id)  => closeTab(id));
ipcMain.on('tab:duplicate', (_, id)  => { const t = tabMap.get(id); if (t) createTab(t.url); });
ipcMain.on('tab:pin',  (_, id) => {
  const t = tabMap.get(id);
  if (!t) return;
  t.pinned = !t.pinned;
  send('tab:update', tabData(t));
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
ipcMain.on('nav:back',        (_, id) => { const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goBack(); });
ipcMain.on('nav:forward',     (_, id) => { const t = tabMap.get(id); ensureBvAttached(t); t?.bv.webContents.goForward(); });
ipcMain.on('nav:reload',      (_, id) => { const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reload(); });
ipcMain.on('nav:reload:hard', (_, id) => { const t = tabMap.get(id); if (t?.url === 'newtab') return; ensureBvAttached(t); t?.bv.webContents.reloadIgnoringCache(); });
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

// ── Panel keep-alive: prevent videos/animations from pausing while BV is detached ──
const PANEL_KEEP_ALIVE_JS = `(function(){
  if (window._rbPanelOpen) return;
  window._rbPanelOpen = true;
  // Override visibility so browsers/players don't pause on BV detach
  Object.defineProperty(document, 'hidden', { get: () => false, configurable: true });
  Object.defineProperty(document, 'visibilityState', { get: () => 'visible', configurable: true });
  // Swallow visibilitychange before it reaches any pause handlers
  window._rbVCBlock = function(e) { e.stopImmediatePropagation(); };
  document.addEventListener('visibilitychange', window._rbVCBlock, true);
})()`;
const PANEL_RESTORE_ALIVE_JS = `(function(){
  if (!window._rbPanelOpen) return;
  window._rbPanelOpen = false;
  try { delete document.hidden; } catch {}
  try { delete document.visibilityState; } catch {}
  if (window._rbVCBlock) {
    document.removeEventListener('visibilitychange', window._rbVCBlock, true);
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
ipcMain.on('panel:show', () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') return;
  const wc = tab.bv.webContents;
  // 1. Cleanly pause any playing media BEFORE capture so the screenshot shows a
  //    stable frame (prevents YouTube "grey-out" caused by mid-frame BV detach).
  const pauseJs = `(function(){try{document.querySelectorAll('video,audio').forEach(function(m){m._rbP=m.paused;if(!m.paused)m.pause();})}catch(e){}})()`;
  wc.executeJavaScript(pauseJs).catch(() => {})
    .then(() => {
      if (!panelOpen) return Promise.reject('closed');
      return wc.capturePage(); // 2. Capture WHILE BV still attached — never black
    })
    .then(img => {
      if (!panelOpen) return;
      try { win.removeBrowserView(tab.bv); } catch {} // 3. Remove BV
      send('panel:snapshot', img.toDataURL());         // 4. Send live screenshot
    })
    .catch(() => {
      // Fallback: just remove BV, no screenshot
      if (!panelOpen) return;
      try { win.removeBrowserView(tab.bv); } catch {}
    });
});
ipcMain.on('panel:show:quick', () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (tab?.bv) {
    try {
      win.removeBrowserView(tab.bv);
    } catch {}
  }
});
// Inject keep-alive JS into BV but do NOT remove it — panel will appear in clipped area
ipcMain.on('panel:show:keepalive', async () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') return;
  await tab.bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
});
// Resize BV to leave right-side room for the open panel (so panel HTML shows above BV)
ipcMain.on('panel:clip', (_, x) => {
  panelClipX = Math.max(0, x || 0);
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab' && !tab.bv.webContents.isDestroyed()) setBounds(tab.bv);
});
ipcMain.on('panel:show:fast', () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') return;
  const bv = tab.bv;
  // Capture FIRST while BV compositor still has its rendered frame,
  // then inject keep-alive JS (so videos/animations continue), then remove BV.
  bv.webContents.capturePage()
    .then(async img => {
      if (!panelOpen) return;
      await bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
      try { win.removeBrowserView(bv); } catch {}
      send('panel:snapshot', img.toDataURL());
    })
    .catch(() => {
      if (!panelOpen) return;
      try { win.removeBrowserView(bv); } catch {}
    });
});
ipcMain.on('panel:show:nowait', async () => {
  // Instant open — no capture, no snapshot shown. Used for overlays that cover everything.
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') return;
  await tab.bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
  if (!panelOpen) return;
  try { win.removeBrowserView(tab.bv); } catch {}
});
ipcMain.on('panel:show:instant', async () => {
  // Instant open WITH website visible — uses cached snapshot if available, else live capture
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') return;
  const bv = tab.bv;
  if (tab.snapshot) {
    // Cached snapshot — inject keep-alive, remove BV, show cached image instantly
    await bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
    if (!panelOpen) return;
    try { win.removeBrowserView(bv); } catch {}
    send('panel:snapshot', tab.snapshot);
  } else {
    // No cache — live capture (first-open fallback)
    bv.webContents.capturePage()
      .then(async img => {
        if (!panelOpen) return;
        await bv.webContents.executeJavaScript(PANEL_KEEP_ALIVE_JS).catch(() => {});
        try { win.removeBrowserView(bv); } catch {}
        send('panel:snapshot', img.toDataURL());
      })
      .catch(() => {
        if (!panelOpen) return;
        try { win.removeBrowserView(bv); } catch {}
      });
  }
});
ipcMain.on('panel:hide', () => {
  panelOpen = false;
  panelClipX = 0;   // always restore full BV width
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') {
    // Re-add BV if it was removed (snapshot mode), then restore full-width bounds
    try { win.addBrowserView(tab.bv); } catch {}
    try { setBounds(tab.bv); } catch {}
    tab.bv.webContents.executeJavaScript(PANEL_RESTORE_ALIVE_JS).catch(() => {});
  }
  send('panel:snapshot:clear');
});
ipcMain.on('sidebar:toggle', (_, show) => {
  sidebarOn = !!show;
  const tab = tabMap.get(activeId);
  if (tab?.bv && !panelOpen && tab.url !== 'newtab') setBounds(tab.bv);
});

// ── IPC: Snip tool ────────────────────────────────────────────────────────────
ipcMain.on('snip:start', () => {
  panelOpen = true;
  const tab = tabMap.get(activeId);
  if (!tab?.bv || tab.url === 'newtab') { send('snip:ready', null); return; }
  tab.bv.webContents.capturePage().then(img => {
    try { win.removeBrowserView(tab.bv); } catch {}
    send('snip:ready', img.toDataURL());
  }).catch(() => {
    try { win.removeBrowserView(tab.bv); } catch {}
    send('snip:ready', null);
  });
});
ipcMain.on('snip:cancel', () => {
  panelOpen = false;
  const tab = tabMap.get(activeId);
  if (tab?.bv && tab.url !== 'newtab') try { win.addBrowserView(tab.bv); setBounds(tab.bv); } catch {}
});
ipcMain.on('snip:save', async (_, dataURL) => {
  panelOpen = false;
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
ipcMain.on('downloads:open',   (_, p) => shell.openPath(p).catch(() => {}));
ipcMain.on('downloads:reveal', (_, p) => shell.showItemInFolder(p));

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