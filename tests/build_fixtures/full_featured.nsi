; Test fixture: exercises many NSIS features for comprehensive testing.
; LZMA solid, Unicode, multiple sections, pages, registry, shortcuts,
; plugin calls, exec, uninstaller.
SetCompressor /SOLID lzma
Unicode true
Name "Full Featured Test"
OutFile "full_featured.exe"
InstallDir "$PROGRAMFILES\FullFeaturedTest"

!include "MUI2.nsh"

; Pages
!insertmacro MUI_PAGE_LICENSE "payload.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; Callbacks
Function .onInit
  MessageBox MB_OK "Initializing..."
FunctionEnd

Section "Core Files" SEC_CORE
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"

  ; Registry
  WriteRegStr HKLM "Software\FullFeaturedTest" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\FullFeaturedTest" "Version" "1.0.0"
  WriteRegDWORD HKLM "Software\FullFeaturedTest" "MajorVersion" 1
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FullFeaturedTest" "DisplayName" "Full Featured Test"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FullFeaturedTest" "UninstallString" '"$INSTDIR\uninstall.exe"'

  ; Shortcuts
  CreateDirectory "$SMPROGRAMS\FullFeaturedTest"
  CreateShortcut "$SMPROGRAMS\FullFeaturedTest\Readme.lnk" "$INSTDIR\payload.txt"
  CreateShortcut "$DESKTOP\FullFeaturedTest.lnk" "$INSTDIR\payload.txt"

  ; Uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Optional Docs" SEC_DOCS
  SetOutPath "$INSTDIR\docs"
  File "payload.txt"
SectionEnd

Section "un.Uninstaller"
  Delete "$INSTDIR\payload.txt"
  Delete "$INSTDIR\config.ini"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR\docs"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\FullFeaturedTest"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FullFeaturedTest"
  Delete "$SMPROGRAMS\FullFeaturedTest\Readme.lnk"
  RMDir "$SMPROGRAMS\FullFeaturedTest"
  Delete "$DESKTOP\FullFeaturedTest.lnk"
SectionEnd
