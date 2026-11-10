param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Channel = "",
    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$binary = Join-Path $root "target\x86_64-pc-windows-msvc\release\pfx-pem.exe"
if (-not (Test-Path $binary)) {
    throw "Missing release binary: $binary"
}

$stageName = "pfx-pem-$Version$Channel-windows-x64"
$stage = Join-Path $root "target\package\$stageName"
$destination = Join-Path $root $OutDir

if (Test-Path $stage) {
    Remove-Item -Recurse -Force $stage
}
New-Item -ItemType Directory -Force -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path $destination | Out-Null

Copy-Item $binary (Join-Path $stage "pfx-pem.exe")
Copy-Item (Join-Path $root "LICENSE") (Join-Path $stage "LICENSE.txt")
Copy-Item (Join-Path $root "THIRD_PARTY.md") (Join-Path $stage "THIRD_PARTY.md")
Copy-Item (Join-Path $root "LICENSES\OpenSSL.txt") (Join-Path $stage "OpenSSL-LICENSE.txt")

$readme = @"
PFX ↔ PEM Converter $Version — Windows x64
================================================

1. Extract this archive to a folder you can write to.
2. Run pfx-pem.exe.

The application is portable: no installer, no admin rights, and no separate
OpenSSL installation are required. Everything is bundled in the exe.

SmartScreen may warn because the build is not code-signed. Choose
"More info" → "Run anyway".

The application works fully offline.

More information and checksums:
https://github.com/mcipovic/pfx-pem-converter/releases
"@

Set-Content -Path (Join-Path $stage "README.txt") -Value $readme -Encoding UTF8

$archive = Join-Path $destination "$stageName.zip"
if (Test-Path $archive) {
    Remove-Item -Force $archive
}
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $archive

Write-Host "created $OutDir/$stageName.zip"
