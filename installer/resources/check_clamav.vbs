' CyberFence Endpoint Installer — ClamAV Detection Script
' check_clamav.vbs
'
' Called as a WiX Custom Action (immediate, VBScript).
' Walks the system PATH searching for clamscan.exe.
' Sets MSI properties:
'   CLAMAV_FOUND = "1"  (string) if found
'   CLAMAV_PATH  = full path to clamscan.exe directory
'
' Returns without error either way — install continues regardless.

Dim oShell, oFSO
Dim sPath, sPaths, sClam
Dim bFound

Set oShell = CreateObject("WScript.Shell")
Set oFSO   = CreateObject("Scripting.FileSystemObject")

bFound = False
sClam  = ""

' ── 1. Walk PATH entries ──────────────────────────────────────────────────
On Error Resume Next
sPaths = oShell.ExpandEnvironmentStrings("%PATH%")
On Error GoTo 0

Dim aPath
aPath = Split(sPaths, ";")

Dim i
For i = 0 To UBound(aPath)
    sPath = Trim(aPath(i))
    If Len(sPath) > 0 Then
        Dim sCandidate
        sCandidate = sPath & "\clamscan.exe"
        If oFSO.FileExists(sCandidate) Then
            bFound = True
            sClam  = sPath
            Exit For
        End If
    End If
Next

' ── 2. Check common ClamAV install directories if not on PATH ─────────────
If Not bFound Then
    Dim aCommon(5)
    aCommon(0) = oShell.ExpandEnvironmentStrings("%ProgramFiles%\ClamAV")
    aCommon(1) = oShell.ExpandEnvironmentStrings("%ProgramFiles(x86)%\ClamAV")
    aCommon(2) = "C:\ClamAV"
    aCommon(3) = "C:\Program Files\ClamAV"
    aCommon(4) = "C:\Program Files (x86)\ClamAV"
    aCommon(5) = oShell.ExpandEnvironmentStrings("%ProgramData%\ClamAV")

    Dim j
    For j = 0 To UBound(aCommon)
        Dim sCandCommon
        sCandCommon = aCommon(j) & "\clamscan.exe"
        If oFSO.FileExists(sCandCommon) Then
            bFound = True
            sClam  = aCommon(j)
            Exit For
        End If
    Next
End If

' ── 3. Set MSI properties via Session object ──────────────────────────────
If bFound Then
    Session.Property("CLAMAV_FOUND") = "1"
    Session.Property("CLAMAV_PATH")  = sClam
Else
    Session.Property("CLAMAV_FOUND") = "0"
    Session.Property("CLAMAV_PATH")  = ""
End If

Set oFSO   = Nothing
Set oShell = Nothing
