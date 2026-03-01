'use strict';

// Raw Browser — Built-in Blocklist
// Covers ads, trackers, telemetry, fingerprinting, crypto miners, malware, and more.
// This is the fallback when EasyList/EasyPrivacy haven't loaded yet.

const BLOCK_DOMAINS = new Set([
  // ── Google Ads & Tracking ──
  'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
  'googletagmanager.com', 'googletagservices.com', 'google-analytics.com',
  'ssl.google-analytics.com', 'stats.g.doubleclick.net', 'analytics.google.com',
  'pagead2.googlesyndication.com', 'adservice.google.com', 'adservice.google.co.uk',
  'tpc.googlesyndication.com', 'csi.gstatic.com',

  // ── Meta / Facebook ──
  'connect.facebook.net', 'facebook.net', 'pixel.facebook.com',
  'an.facebook.com', 'graph.facebook.com', 'web.facebook.com',

  // ── Twitter / X ──
  'ads.twitter.com', 'syndication.twitter.com', 'platform.twitter.com',
  't.co', 'analytics.twitter.com',

  // ── Microsoft Telemetry ──
  'bat.bing.com', 'clarity.ms', 'dc.services.visualstudio.com',
  'browser.pipe.aria.microsoft.com', 'vortex.data.microsoft.com',
  'settings-win.data.microsoft.com', 'telemetry.microsoft.com',
  'watson.telemetry.microsoft.com', 'oca.telemetry.microsoft.com',
  'sqm.telemetry.microsoft.com', 'watson.microsoft.com',
  'redir.metaservices.microsoft.com', 'choice.microsoft.com',
  'df.telemetry.microsoft.com', 'reports.wes.df.telemetry.microsoft.com',

  // ── Amazon Ads ──
  'amazon-adsystem.com', 'aax.amazon-adsystem.com',
  'fls-na.amazon.com', 's.amazon-adsystem.com',

  // ── Ad Networks ──
  'adnxs.com', 'advertising.com', 'adtech.com', 'adtechstack.net',
  'rubiconproject.com', 'pubmatic.com', 'openx.net', 'openx.com',
  'contextweb.com', 'casalemedia.com', 'criteo.com', 'criteo.net',
  'outbrain.com', 'taboola.com', 'revcontent.com', 'mgid.com',
  'adsrvr.org', 'quantserve.com', 'addthis.com', 'sharethis.com',
  '3lift.com', 'appnexus.com', 'bidswitch.net', 'smartadserver.com',
  'sovrn.com', 'indexexchange.com', 'districtm.io', 'sharethrough.com',
  'yieldmo.com', '33across.com', 'rhythmone.com', 'improvedigital.com',
  'spotxchange.com', 'spotx.tv', 'freewheel.tv', 'fwmrm.net', 'lkqd.net',
  'media.net', 'zemanta.com', 'adform.net', 'mathtag.com', 'bkrtx.com',
  'rlcdn.com', 'rfihub.com', 'acuityads.com', 'justpremium.com',
  'adhese.com', 'adition.com', 'sonobi.com', 'undertone.com',
  'lijit.com', 'polar.me', 'iponweb.net', 'yieldlove.com',
  'adtelligent.com', 'smartclip.net', 'springserve.com',
  'adaptv.advertising.com', '360yield.com', 'adblade.com',
  'ampliffy.com', 'bidtellect.com', 'conversant.com', 'tremorvideo.com',
  'videologygroup.com', 'advertising.aol.com', 'advertising.yahoo.com',
  'overture.com', 'yldbt.com', 'synacor.com',

  // ── Analytics & Metrics ──
  'scorecardresearch.com', 'omtrdc.net', 'demdex.net',
  'hotjar.com', 'crazyegg.com', 'fullstory.com', 'logrocket.com',
  'heapanalytics.com', 'mixpanel.com', 'amplitude.com',
  'segment.io', 'segment.com', 'intercom.io', 'intercomcdn.com',
  'chartbeat.com', 'chartbeat.net', 'newrelic.com', 'nr-data.net',
  'speedcurve.com', 'sentry.io', 'bugsnag.com', 'rollbar.com',
  'snap.licdn.com', 'tealiumiq.com', 'ensighten.com',
  'optimizely.com', 'abtasty.com', 'vwo.com', 'kameleoon.com',
  'appsflyer.com', 'branch.io', 'adjust.com', 'kochava.com',
  'singular.net', 'tune.com', 'moengage.com', 'clevertap.com',
  'braze.com', 'appboy.com', 'leanplum.com', 'urbanairship.com',

  // ── Fingerprinting ──
  'fingerprintjs.com', 'fingerprint.com', 'fpnpmcdn.net',
  'deviceatlas.com', 'scientiamobile.com', 'maxmind.com',
  'threatmetrix.com', 'iovation.com', 'limelightnetworks.com',
  'tiqcdn.com', 'thirdlight.com',

  // ── Data Brokers / DMPs ──
  'bluekai.com', 'exelate.com', 'nexac.com', 'lotame.com',
  'turn.com', 'agkn.com', 'eyeota.net', 'bizo.com',
  'dotomi.com', 'krxd.net', 'permutive.com', 'audigent.com',
  'zeotap.com', 'neustar.biz', 'acxiom.com', 'experian.com',
  'liveramp.com', 'identitylink.io', 'tapad.com', 'crossix.com',
  'datalogix.com', 'cardlytics.com', 'epsilon.com', 'merkle.com',
  'viant.com', 'adsquare.com', 'factual.com', 'nuedata.com',

  // ── Social Widgets ──
  'platform.linkedin.com', 'badges.linkedin.com',
  'assets.pinterest.com', 'log.pinterest.com',
  'disqus.com', 'disquscdn.com',
  'staticxx.facebook.com', 'web.facebook.com',

  // ── Crypto Miners ──
  'coinhive.com', 'coin-hive.com', 'minero.cc', 'cryptoloot.pro',
  'miner.pr0gramm.com', 'jsecoin.com', 'cryptonight.com',
  'webminepool.com', 'ppoi.org', 'authedmine.com',
  'listat.biz', 'lmodr.biz', 'minecrunch.co', 'minemytraffic.com',

  // ── Malware / Scam ──
  'popcash.net', 'popads.net', 'pop-under.ru',
  'zeroredirect1.com', 'zeroredirect2.com',
  'malvertising.com', 'trafficholder.com',

  // ── Cookie Consent (tracking) ──
  'onetrust.com', 'cookielaw.org', 'cookiebot.com',
  'trustarc.com', 'evidon.com', 'ghostery.com',

  // ── Russian Telemetry ──
  'tns-counter.ru', 'counter.ok.ru', 'mc.yandex.ru',
  'metrika.yandex.ru', 'an.yandex.ru', 'yabs.yandex.ru',
  'mail.yandex.ru', 'carambola.ru',

  // ── Chinese Telemetry ──
  'cnzz.com', 'umeng.com', 'alog.umengcloud.com',
  'mmstat.com', 'alipayobjects.com',

  // ── Push Notification Spam ──
  'pushcrew.com', 'onesignal.com', 'pushengage.com',
  'web-push-notifications.com', 'pushassist.com',
  'gravitec.net', 'sendpulse.com', 'pushwoosh.com',

  // ── Session Recording ──
  'mouseflow.com', 'usabilla.com', 'inspectlet.com',
  'luckyorange.com', 'clicktale.com', 'quantummetric.com',
  'glassbox.com', 'sessioncam.com', 'decibel-insight.com',

  // ── A/B Testing / CRO ──
  'googleoptimize.com', 'qubit.com', 'conductrics.com',
  'monetate.net', 'certona.net', 'evergage.com',

  // ── Marketing Automation ──
  'marketo.net', 'pardot.com', 'hubspot.com', 'hubspot.net',
  'hs-analytics.net', 'hs-banner.com', 'hscta.net',
  'eloqua.com', 'responsys.net', 'exacttarget.com',
  'silverpop.com', 'sailthru.com', 'sendgrid.net',
  'mailchimp.com', 'list-manage.com', 'klaviyo.com',

  // ── Retargeting ──
  'rtbhouse.com', 'criteo.com', 'adroll.com', 'perfectaudience.com',
  'triggit.com', 'steelhouse.com', 'fetchback.com',
  'chango.com', 'buyads.com', 'retargeter.com',

  // ── CDN-hosted trackers ──
  'cdn.mxpnl.com', 'js.hs-analytics.net', 'js.hsforms.net',
  'js.hscta.net', 'js.hs-banner.com',

  // ── Supply Side Platforms ──
  'appnexus.com', 'openx.com', 'rubiconproject.com',
  'pubmatic.com', 'rocketfuel.com', 'priceline.com',
  'advertising.microsoft.com', 'media.net',

  // ── Demand Side Platforms ──
  'mediamath.com', 'thetradedesk.com', 'dataxu.com',
  'adobe.com', 'adobedtm.com', 'demdex.com',

  // ── Browser Telemetry / Update pings ──
  'safebrowsing.googleapis.com', 'safebrowsing.google.com',
  'update.googleapis.com', 'clients2.google.com',
  'sb.google.com', 'sb-ssl.google.com',

  // ── Apple Telemetry ──
  'metrics.apple.com', 'pancake.apple.com',
  'xp.apple.com', 'configuration.apple.com',

  // ── General tracker patterns (hosted explicitly) ──
  'tracking.com', 'tracker.com', 'trackingprotection.com',
  'adtrack.com', 'adtracking.com', 'usertrack.com',
  'emailtracking.com', 'mailtracking.com',
  'statcounter.com', 'woopra.com', 'kissmetrics.com',
  'gaug.es', 'getclicky.com', 'clicky.com',

  // ── Supply chain / header bidding ──
  'liveintent.com', 'bidmachine.io', 'emxdgt.com',
  'aniview.com', 'teads.tv', 'teads.com',
  'sharethrough.com', 'triplelift.com', 'nobid.io',
  'nexxen.com', 'unrulymedia.com', 'rhythmone.com',

  // ── Misc high-confidence trackers ──
  'addthis.com', 'outbrain.com', 'taboola.com',
  'revcontent.com', 'mgid.com', 'zergnet.com',
  'ligatus.com', 'nativo.com', 'plista.com',
  'shareaholic.com', 'socialspark.com', 'blogads.com',
  'adsonar.com', 'advertising.com', 'atwola.com',
  'advertising.aol.com',
]);

// Regex patterns for catching tracker subdomains dynamically
const BLOCK_PATTERNS = [
  /^ads?\d*\./i,
  /^ad\d+\./i,
  /\.ads?\./i,
  /^track(ing|er)?\d*\./i,
  /^pixel\d*\./i,
  /^beacon\d*\./i,
  /^telemetry\d*\./i,
  /^analytics?\d*\./i,
  /^collect\d*\./i,
  /^metrics?\d*\./i,
  /^stats?\d*\./i,
  /^(gtm|tag|stm)\./i,
  /^log(ger|ging)?\d*\./i,
  /^event(s)?\./i,
  /^ping\./i,
  /^hit\./i,
  /^impression\./i,
  /^conv(ersion)?\./i,
  /^retarget(ing)?\./i,
  /^remarketing\./i,
  /^dmp\./i,
  /^audience\./i,
  /^segment\./i,
  /^report(ing|s)?\./i,
  /^miner\./i,
  /^mine\./i,
  /^crypto.*mine/i,
];

// Never block these no matter what
const WHITELIST = new Set([
  'youtube.com', 'www.youtube.com', 'youtu.be',
  'tiktok.com', 'www.tiktok.com',
  'twitter.com', 'x.com', 't.co',
  'instagram.com', 'www.instagram.com',
  'facebook.com', 'www.facebook.com', 'm.facebook.com',
  'reddit.com', 'www.reddit.com', 'old.reddit.com',
  'twitch.tv', 'www.twitch.tv', 'static.twitchsvc.net',
  'discord.com', 'discordapp.com', 'discordcdn.com',
  'slack.com', 'slack-edge.com',
  'zoom.us', 'us02web.zoom.us',
  'netflix.com', 'www.netflix.com',
  'spotify.com', 'open.spotify.com',
  'github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com',
  'gitlab.com',
  'stackoverflow.com', 'stackexchange.com',
  'wikipedia.org', 'wikimedia.org',
  'google.com', 'www.google.com', 'accounts.google.com', 'mail.google.com',
  'gstatic.com', 'googleapis.com', 'google.co.uk', 'google.de',
  'amazon.com', 'www.amazon.com', 'images-na.ssl-images-amazon.com',
  'cloudfront.net', 'fastly.net', 'akamaized.net', 'akamai.net',
  'cdn77.com', 'cdnjs.cloudflare.com', 'cloudflare.com',
  'unpkg.com', 'jsdelivr.net',
  'apple.com', 'icloud.com', 'mzstatic.com',
  'microsoft.com', 'live.com', 'office.com', 'microsoft365.com',
  'nytimes.com', 'theguardian.com', 'bbc.com', 'bbc.co.uk',
  'cnn.com', 'reuters.com', 'apnews.com',
]);

function isWhitelisted(host) {
  if (WHITELIST.has(host)) return true;
  for (const w of WHITELIST) {
    if (host.endsWith('.' + w)) return true;
  }
  return false;
}

function shouldBlock(url, adblockEnabled) {
  if (!adblockEnabled) return false;
  
  try {
    const urlObj = new URL(url);
    let host = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    
    if (isWhitelisted(host)) return false;
    if (BLOCK_DOMAINS.has(host)) return true;
    
    // Check parent domains
    const parts = host.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      if (BLOCK_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }
    
    // Pattern matching
    for (const pattern of BLOCK_PATTERNS) {
      if (pattern.test(host)) return true;
    }
  } catch (e) {
    // Invalid URL - return false to avoid breaking
    return false;
  }
  
  return false;
}

module.exports = { shouldBlock, isWhitelisted, BLOCK_DOMAINS, BLOCK_PATTERNS, WHITELIST };