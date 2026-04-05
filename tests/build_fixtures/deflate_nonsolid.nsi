; Test fixture: deflate (zlib), non-solid, Unicode
; Default compressor is zlib non-solid
Unicode true
Name "Deflate NonSolid Test"
OutFile "deflate_nonsolid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
