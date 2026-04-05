; Test fixture: ANSI mode (no Unicode), deflate non-solid
; Omitting "Unicode true" gives ANSI mode
Name "ANSI Deflate Test"
OutFile "ansi_deflate.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
SectionEnd
