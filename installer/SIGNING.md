# CyberFence Endpoint — Code Signing Guide

Signing the MSI with a trusted certificate eliminates "Unknown Publisher" warnings
on Windows and is required for enterprise deployment via Intune/SCCM.

---

## Option A — Self-Signed (Development / Internal Testing)

```powershell
# 1. Create a self-signed code-signing cert (valid 3 years)
$cert = New-SelfSignedCertificate `
  -Type CodeSigningCert `
  -Subject "CN=CyberFence Endpoint, O=Perez Technology Group, C=US" `
  -KeyUsage DigitalSignature `
  -FriendlyName "CyberFence Dev Signing" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -NotAfter (Get-Date).AddYears(3)

# 2. Get the thumbprint
$cert.Thumbprint

# 3. Build and sign
.\installer\scripts\build.ps1 -SignCert $cert.Thumbprint
```

Self-signed certs will show a SmartScreen warning. Acceptable for internal use.

---

## Option B — DigiCert OV/EV Certificate (Production)

DigiCert is the recommended CA for Windows code signing.

### Purchase
1. Go to https://www.digicert.com/signing/code-signing-certificates
2. Choose **OV Code Signing** ($474/yr) or **EV Code Signing** ($699/yr, no SmartScreen)
3. Complete organization validation (3-5 business days for OV, 1-2 weeks for EV)

### Once issued

```powershell
# Import the .pfx into your cert store
Import-PfxCertificate -FilePath "CyberFence_CodeSign.pfx" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -Password (Read-Host -AsSecureString "PFX Password")

# Get thumbprint
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*CyberFence*" }

# Build and sign
.\installer\scripts\build.ps1 -SignCert "<thumbprint>"
```

### Timestamp server
The build script uses DigiCert's RFC 3161 timestamp server:
`http://timestamp.digicert.com`

This ensures the signature remains valid even after the certificate expires.

---

## Option C — Sign the Pre-Built MSI (without rebuilding)

```powershell
$SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe"

& $SignTool sign `
  /sha1 "<thumbprint>" `
  /td sha256 `
  /fd sha256 `
  /tr "http://timestamp.digicert.com" `
  /d  "CyberFence Endpoint Protection Agent" `
  /du "https://www.cyberfenceplatform.com" `
  "dist\CyberFence-Endpoint-v0.1.0.msi"

# Verify
& $SignTool verify /pa /v "dist\CyberFence-Endpoint-v0.1.0.msi"
```

---

## Option D — Azure Trusted Signing (GitHub Actions CI)

For automated signing in CI/CD pipelines:

```yaml
# .github/workflows/release.yml
- name: Sign MSI
  uses: azure/trusted-signing-action@v0.4.0
  with:
    azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
    azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
    endpoint: https://eus.codesigning.azure.net/
    trusted-signing-account-name: cyberfence-signing
    certificate-profile-name: CyberFenceEndpoint
    files-folder: dist
    files-folder-filter: "*.msi"
    file-digest: SHA256
    timestamp-rfc3161: http://timestamp.acs.microsoft.com
    timestamp-digest: SHA256
```

---

## Verify a Signed MSI

```powershell
# Check signature
Get-AuthenticodeSignature "dist\CyberFence-Endpoint-v0.1.0.msi" | Format-List

# Detailed signtool verify
signtool verify /pa /v "dist\CyberFence-Endpoint-v0.1.0.msi"
```

Expected output for valid EV-signed installer:
```
Successfully verified: CyberFence-Endpoint-v0.1.0.msi
Number of files successfully Verified: 1
```
