' CyberFence Endpoint Installer — ClamAV Missing Warning
' warn_no_clamav.vbs
'
' Fires only when CLAMAV_FOUND = "0" (condition set in Product.wxs).
' Shows a non-blocking dialog explaining ClamAV is required for scan
' functionality. User can still complete the install.

Dim oShell
Set oShell = CreateObject("WScript.Shell")

Dim sMsg
sMsg = "CyberFence Scan Engine (ClamAV) Not Detected" & vbCrLf & vbCrLf & _
       "The CyberFence Engine requires ClamAV to be installed on this machine " & _
       "to perform malware scanning." & vbCrLf & vbCrLf & _
       "You can still install the CyberFence Endpoint Agent now, but scanning " & _
       "will be disabled until ClamAV is installed." & vbCrLf & vbCrLf & _
       "To install ClamAV:" & vbCrLf & _
       "  1. Download from: https://www.clamav.net/downloads" & vbCrLf & _
       "  2. Run the ClamAV installer" & vbCrLf & _
       "  3. Run 'freshclam' to update virus definitions" & vbCrLf & _
       "  4. Restart the CyberFenceAgent Windows Service" & vbCrLf & vbCrLf & _
       "Click OK to continue the CyberFence installation."

oShell.Popup sMsg, 0, "CyberFence Endpoint — ClamAV Not Found", 48

Set oShell = Nothing
