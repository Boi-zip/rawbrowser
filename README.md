# RAW Browser

A privacy-first desktop browser built on Electron. No telemetry, no data collection, no phone-home — just a fast, clean browser that works for you.

---

## Features

### Privacy & Security
- **Built-in ad & tracker blocking** — blocklist-based blocking with 100k+ rules, applied at the network layer before requests even leave your machine
- **Fingerprint spoofing** — randomises your browser fingerprint (user agent, screen resolution, platform, language, hardware) so sites can't identify you across sessions
- **WebRTC IP leak protection** — forces all WebRTC traffic through relay, blocks non-proxied UDP to prevent IP leaks
- **Tracking parameter stripping** — removes UTM, fbclid, gclid and other tracking params from URLs automatically
- **Beacon blocking** — `navigator.sendBeacon` is blocked in-page
- **Referrer scrubbing** — cross-origin referrer headers are stripped to origin-only at the network layer
- **Permission guard** — geolocation, notifications, sensors, NFC and bluetooth are denied by default

### Location Masking
- Spoof your GPS coordinates to any of 50 cities across 5 regions
- Works by overriding `navigator.geolocation` in-page — sites receive fake coordinates
- Enable from the toolbar pin icon; select a city from the panel
- Agreement screen explains what it does and what it doesn't (not a VPN)

### Poison Data
- Floods trackers with fake signals — fake location, fake persona, randomised cookie noise
- Useful on sites you can't block entirely — you show up as noise in their datasets
- Toggle per-site from the toolbar bug icon

### Ad Blocking
- Block rules applied via `onBeforeRequest` — ads never load, no wasted bandwidth
- YouTube ad skip — fast-forwards video ads instead of blocking (avoids YouTube's detection)
- Whitelist any domain from the Privacy panel or Settings → Whitelist

### Media Controls
- When a tab is playing audio, an animated waveform button appears in the toolbar
- Click it to open the **Now Playing** panel showing all audio-active tabs
- Each tab has: ← 10s skip, mute toggle, +10s skip, and a switch-to-tab button
- Mute individual tabs by hovering over them in the tab bar — a speaker icon appears; click to mute

### Video Downloader
- Downloads videos from YouTube, Vimeo, Twitter/X, Reddit and 1000+ other sites via [yt-dlp](https://github.com/yt-dlp/yt-dlp)
- Auto-downloads the yt-dlp binary on first use (no setup required)
- Choose output folder, quality and format from the panel
- Progress bar with speed and ETA shown in the Downloads panel

### Picture-in-Picture
- Every video gets a floating **Pop Out** button on hover
- Click it to detach the video into a resizable floating window
- Works on YouTube, Netflix, Twitch, Vimeo and most sites

### Add-Ons (built-in extensions)
| Add-On | What it does |
|---|---|
| Dark Mode | Forces dark colour scheme on any site |
| No Animations | Disables CSS transitions and animations |
| Video Speed | Adds a speed controller overlay to videos |
| Focus Mode | Hides sidebars, comments and distractions |
| Grayscale | Renders the page in greyscale |
| Night Filter | Applies a warm amber overlay |
| Remove Banners | Hides cookie banners and GDPR popups |
| Highlight Links | Underlines and tints all links |
| Scroll Progress | Shows a reading progress bar at the top |
| Font Boost | Increases base font size by 20% |
| Reader Mode | Strips pages to text and images |
| Image Zoom | Click any image to expand it |
| Word Count | Shows live word count in a corner badge |
| Anti-Tracking | Blocks common tracking scripts not caught by the blocklist |
| Print Clean | Strips ads and nav from print view |

Enable add-ons from the **Add-Ons** button (puzzle piece icon) in the toolbar.

### Notes
- Persistent per-device notepad, stored locally in `localStorage`
- Multi-note support — create, title, auto-save with 800ms debounce
- Access from the toolbar notes icon (off by default, enable in Settings → Toolbar)

### Calculator
- Full scientific calculator panel
- Standard mode: +, −, ×, ÷, %, ±
- SCI mode: sin, cos, tan (degrees), π, √, x², log, e, asin, acos, atan, ∛, x³, ln, τ, eˣ
- Access from the toolbar calc icon (off by default, enable in Settings → Toolbar)

### Downloads
- Active downloads shown with live speed (bytes/sec) and ETA
- Completed downloads listed below with file size and open/reveal buttons
- Right-click the Downloads button to see active downloads without opening the panel

### Bookmarks
- One-click bookmark from the star button in the toolbar
- Bookmark panel lists all bookmarks with search
- Open bookmark panel from the stacked-star icon

### History
- Full browsing history with search
- Click any item to navigate, or hover for the full URL
- Clear history from the panel header

### Translate
- Translate any page via Google Translate
- Set your target language in Settings → Translate
- Trigger from the right-click context menu → Translate Page

### Sidebar
- Pinned sites open in a persistent sidebar on the left
- Add any site: right-click in the sidebar and choose Add Site
- Toggle sidebar from Settings → Appearance

### Screenshot (Snip)
- Capture the full visible page or a region
- `Ctrl+Shift+S` or the scissors icon in the toolbar

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+T` | New tab |
| `Ctrl+W` | Close tab |
| `Ctrl+Tab` | Next tab |
| `Ctrl+Shift+Tab` | Previous tab |
| `Ctrl+L` | Focus address bar |
| `Ctrl+R` / `F5` | Reload |
| `Ctrl+Shift+R` | Hard reload (bypass cache) |
| `Alt+Left` | Back |
| `Alt+Right` | Forward |
| `Ctrl+F` | Find in page |
| `Ctrl++` | Zoom in |
| `Ctrl+-` | Zoom out |
| `Ctrl+0` | Reset zoom |
| `Ctrl+Shift+S` | Snip screenshot |
| `Ctrl+M` | Mute/unmute tab |
| `Escape` | Stop loading / close panel |

---

## Settings

Open settings from the **⊞** menu button → Settings, or press `Ctrl+,`.

| Section | Key options |
|---|---|
| **Appearance** | Accent colour, wallpaper, compact mode, sidebar, favicons |
| **Privacy** | Ad blocking, telemetry blocking, fingerprint spoofing, strict privacy, Do Not Track |
| **Search** | Default search engine (DuckDuckGo, Google, Bing, Brave, Startpage, custom) |
| **Performance** | Hardware acceleration |
| **Tabs** | Restore session on launch, open in background, close confirmation, new tab position |
| **Downloads** | Download path, ask before saving, auto-open on completion |
| **Toolbar** | Show/hide individual toolbar buttons |
| **Translate** | Target language for page translation |
| **Whitelist** | Domains exempt from ad blocking |
| **Data** | Clear history, cache, cookies, downloads |
| **About** | Version info |

---

## Building & Running

### Prerequisites

- [Node.js](https://nodejs.org/) v18 or later
- [npm](https://www.npmjs.com/) (bundled with Node.js)
- Git

### Install dependencies

```bash
git clone https://github.com/sharp4real/rawbrowser.git
cd rawbrowser
npm install
```

### Run in development

```bash
npm start
```

### Build distributables

```bash
# Windows
npm run build:win

# macOS
npm run build:mac

# Linux
npm run build:linux
```

Built packages are output to the `dist/` folder.

### Project structure

```
raw-browser/
├── main.js          # Electron main process — tabs, BrowserViews, IPC, blocking
├── index.html       # Browser chrome UI — all panels, settings, JavaScript
├── preload.js       # BrowserView preload — fingerprint spoofing, security patches
├── blocklist.js     # Ad/tracker blocking rules and engine
├── offline.html     # Offline page (canvas platformer game)
├── assets/          # Icons and images
└── package.json
```

### Key architecture notes

- One `BrowserView` per tab, attached to the main `BrowserWindow` at y = chrome height (76px)
- Panels are HTML elements inside the `BrowserWindow` — they become visible by clipping the BV's width
- Settings are persisted to `userData/rawbrowser/settings.json`
- History, bookmarks and downloads are in separate JSON files in the same folder
- yt-dlp binary is downloaded to `userData/rawbrowser/yt-dlp.exe` on first use

---

## Privacy Model

RAW Browser blocks ads and trackers at the network layer, spoofs your fingerprint, and strips tracking data — but it is **not a VPN**. Your IP address is still visible to sites you visit. For network-level anonymity use Tor or a trusted VPN alongside RAW.

The Location Masking feature (`btn-geo`) overrides `navigator.geolocation` in JavaScript only. It does not change your IP geolocation.

No data is sent to any server by RAW Browser itself. The only outbound connections RAW makes on your behalf are:
- Pages you navigate to
- DuckDuckGo autocomplete (only when typing in the new tab search bar)
- yt-dlp update check (on launch, to `github.com/yt-dlp/yt-dlp/releases`)

---

## Status

Beta — actively developed. Expect occasional rough edges. File issues at the repo.
