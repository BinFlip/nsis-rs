; Test fixture: bzip2, solid, Unicode
SetCompressor /SOLID bzip2
Unicode true
Name "Bzip2 Solid Test"
OutFile "bzip2_solid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
