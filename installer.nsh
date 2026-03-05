; installer.nsh — Custom registry writes so Raw Browser appears in
; Windows Settings › Default Apps after installation.
; Follows the exact same structure Chrome/Edge use (StartMenuInternet tree).
; electron-builder calls !macro customInstall / customUnInstall automatically.

!macro customInstall
  ; ── ProgID (RawBrowserHTML) ───────────────────────────────────────────────
  WriteRegStr HKCU "Software\Classes\RawBrowserHTML" \
              "" "Raw Browser HTML Document"
  WriteRegStr HKCU "Software\Classes\RawBrowserHTML" \
              "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\RawBrowserHTML\DefaultIcon" \
              "" "$INSTDIR\Raw.exe,0"
  WriteRegStr HKCU "Software\Classes\RawBrowserHTML\shell\open\command" \
              "" '"$INSTDIR\Raw.exe" "%1"'

  ; ── StartMenuInternet tree ────────────────────────────────────────────────
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Raw Browser" \
                "" "Raw Browser"
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Raw Browser\DefaultIcon" \
                "" "$INSTDIR\Raw.exe,0"
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Raw Browser\shell\open\command" \
                "" '"$INSTDIR\Raw.exe"'
  WriteRegDWORD HKCU "Software\Clients\StartMenuInternet\Raw Browser\InstallInfo" \
                "IconsVisible" 1
  WriteRegStr   HKCU "Software\Clients\StartMenuInternet\Raw Browser\StartMenu" \
                "" "Raw Browser"

  ; ── Capabilities ─────────────────────────────────────────────────────────
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities" \
              "ApplicationName" "Raw Browser"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities" \
              "ApplicationIcon" "$INSTDIR\Raw.exe,0"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities" \
              "ApplicationDescription" "Privacy-first browser — built-in ad blocking, no tracking"

  ; URL associations
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\URLAssociations" \
              "ftp"   "RawBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\URLAssociations" \
              "http"  "RawBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\URLAssociations" \
              "https" "RawBrowserHTML"

  ; File associations
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\FileAssociations" \
              ".htm"   "RawBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\FileAssociations" \
              ".html"  "RawBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\FileAssociations" \
              ".xhtml" "RawBrowserHTML"
  WriteRegStr HKCU "Software\Clients\StartMenuInternet\Raw Browser\Capabilities\FileAssociations" \
              ".pdf"   "RawBrowserHTML"

  ; ── RegisteredApplications — what makes it appear in Default Apps UI ──────
  WriteRegStr HKCU "Software\RegisteredApplications" \
              "Raw Browser" \
              "Software\Clients\StartMenuInternet\Raw Browser\Capabilities"
!macroend

!macro customUnInstall
  ; Clean up all registry keys on uninstall
  DeleteRegKey  HKCU "Software\Classes\RawBrowserHTML"
  DeleteRegKey  HKCU "Software\Clients\StartMenuInternet\Raw Browser"
  DeleteRegValue HKCU "Software\RegisteredApplications" "Raw Browser"
!macroend
