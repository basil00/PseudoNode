; Bitcoin TX Monitor installer
; Copyright (c) 2015 the copyright holders
;
; Permission is hereby granted, free of charge, to any person obtaining a
; copy of this software and associated documentation files (the "Software"),
; to deal in the Software without restriction, including without limitation
; the rights to use, copy, modify, merge, publish, distribute, sublicense,
; and/or sell copies of the Software, and to permit persons to whom the
; Software is furnished to do so, subject to the following conditions:
; 
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
; 
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
; DEALINGS IN THE SOFTWARE.

!include "MUI2.nsh"

SetCompressor /SOLID /FINAL lzma

Name "TxMon"
OutFile "TxMon-install.exe"

InstallDir "$PROGRAMFILES\TxMon\"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section ""
    SetOutPath $INSTDIR
    File "TxMon.exe"
    File "PseudoNode.dll"
    File "miniupnpc.dll"
    File "LICENSE.txt"
    WriteUninstaller "TallowBundle-uninstall.exe"
    CreateShortCut "$DESKTOP\TxMon.lnk" "$INSTDIR\TxMon.exe" ""
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\TxMon.exe"
    Delete "$INSTDIR\PseudoNode.dll"
    Delete "$INSTDIR\miniupnpc.dll"
    Delete "$INSTDIR\LICENSE.txt"
    RMDir "$INSTDIR\"
    Delete "$DESKTOP\TxMon.lnk"
SectionEnd

