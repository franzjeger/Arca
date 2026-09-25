<#
  One-shot installer for the Arca native-messaging host (Windows).

  Builds the host binary and registers it for every Chromium-family browser via
  the per-user registry, with the extension's PINNED id (derived from the public
  `key` in chromium/manifest.json). After running this, the only manual step
  left is Chrome's mandatory "Load unpacked" (Google blocks programmatic
  unpacked installs) — and because the id is pinned, no id-copying is needed.

  Re-runnable and reversible: delete the registry keys it prints, or run
  `Remove-Item` on each, to undo.

  Usage (from the repo root, in PowerShell):
    ./extension/install-windows.ps1
#>
$ErrorActionPreference = 'Stop'

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$HostBin = Join-Path $Repo 'target\release\vault-native-host.exe'
$ChromiumManifest = Join-Path $Repo 'extension\chromium\manifest.json'
$HostName = 'no.sybr.vault'

Write-Host '==> Building the native messaging host (release)...'
Push-Location $Repo
try { cargo build -p vault-native-host --release } finally { Pop-Location }
if (-not (Test-Path $HostBin)) { throw "host binary not found at $HostBin" }

Write-Host '==> Deriving the pinned extension id from the manifest key...'
$key = (Get-Content -Raw $ChromiumManifest | ConvertFrom-Json).key
if ([string]::IsNullOrEmpty($key)) { throw "no `"key`" field in $ChromiumManifest" }
$sha = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Convert]::FromBase64String($key))
$hex = -join ($sha[0..15] | ForEach-Object { $_.ToString('x2') })
$map = @{ '0'='a';'1'='b';'2'='c';'3'='d';'4'='e';'5'='f';'6'='g';'7'='h';
         '8'='i';'9'='j';'a'='k';'b'='l';'c'='m';'d'='n';'e'='o';'f'='p' }
$ExtId = -join ($hex.ToCharArray() | ForEach-Object { $map["$_"] })
Write-Host "    extension id: $ExtId"

# Write the host manifest next to the binary, then point the registry at it.
$manifestPath = Join-Path $Repo 'target\release\no.sybr.vault.json'
$manifest = [ordered]@{
  name            = $HostName
  description     = 'Arca native messaging host'
  path            = $HostBin
  type            = 'stdio'
  allowed_origins = @("chrome-extension://$ExtId/")
}
$manifest | ConvertTo-Json | Set-Content -Encoding UTF8 $manifestPath
Write-Host "==> Wrote host manifest: $manifestPath"

# Chromium-family browsers and their per-user native-messaging registry hives.
$hives = @(
  @{ name = 'Google Chrome'; path = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName" },
  @{ name = 'Chromium';      path = "HKCU:\Software\Chromium\NativeMessagingHosts\$HostName" },
  @{ name = 'Microsoft Edge';path = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName" },
  @{ name = 'Brave';         path = "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\$HostName" }
)
foreach ($h in $hives) {
  New-Item -Path $h.path -Force | Out-Null
  # The (Default) value of the key must be the absolute path to the manifest.
  Set-Item -Path $h.path -Value $manifestPath
  Write-Host "==> Registered for $($h.name): $($h.path)"
}

Write-Host ''
Write-Host 'Done. Last step (Chrome''s one unavoidable click):'
Write-Host '  1. chrome://extensions  ->  enable "Developer mode"'
Write-Host "  2. `"Load unpacked`"  ->  select:  $(Join-Path $Repo 'extension\chromium')"
Write-Host "The extension id will be $ExtId (pinned), matching the registration above."
Write-Host 'Then keep the desktop app open + unlocked and autofill will work.'
