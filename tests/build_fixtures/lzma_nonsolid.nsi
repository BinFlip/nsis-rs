; Test fixture: LZMA, non-solid, Unicode
SetCompressor lzma
Unicode true
Name "LZMA NonSolid Test"
OutFile "lzma_nonsolid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
