; Test fixture: bzip2, non-solid, Unicode
SetCompressor bzip2
Unicode true
Name "Bzip2 NonSolid Test"
OutFile "bzip2_nonsolid.exe"
InstallDir "$TEMP\nsis_test"

Section "Main"
  SetOutPath $INSTDIR
  File "payload.txt"
  File "config.ini"
SectionEnd
