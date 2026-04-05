; Test fixture: deflate (zlib), solid, Unicode
SetCompressor /SOLID zlib
Unicode true
Name "Deflate Solid Test"
OutFile "deflate_solid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
