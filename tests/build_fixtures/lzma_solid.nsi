; Test fixture: LZMA, solid, Unicode
SetCompressor /SOLID lzma
Unicode true
Name "LZMA Solid Test"
OutFile "lzma_solid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
