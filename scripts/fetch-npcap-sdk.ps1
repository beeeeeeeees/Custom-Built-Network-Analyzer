<#
.SYNOPSIS
    Downloads the Npcap SDK needed to build cbna with live-capture support.

.DESCRIPTION
    Live capture links against wpcap, whose import library ships in the Npcap
    SDK rather than the Npcap runtime installer. This script drops the SDK into
    vendor/npcap-sdk, which .cargo/config.toml already points the build at.

    The Npcap *runtime* is a separate install from https://npcap.com and must
    also be present to actually capture. This script only provides the
    build-time headers and import libraries.

.EXAMPLE
    ./scripts/fetch-npcap-sdk.ps1
    cargo build --release --features live
#>
[CmdletBinding()]
param(
    [string]$Version = "1.15",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$vendor = Join-Path $root "vendor"
$sdk = Join-Path $vendor "npcap-sdk"
$lib = Join-Path $sdk "Lib\x64\wpcap.lib"

if ((Test-Path $lib) -and -not $Force) {
    Write-Host "Npcap SDK already present at $sdk (use -Force to re-download)."
    exit 0
}

$url = "https://npcap.com/dist/npcap-sdk-$Version.zip"
$zip = Join-Path $vendor "npcap-sdk-$Version.zip"

New-Item -ItemType Directory -Force $vendor | Out-Null
Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

Write-Host "Extracting to $sdk"
Expand-Archive -Path $zip -DestinationPath $sdk -Force
Remove-Item $zip -Force

if (-not (Test-Path $lib)) {
    throw "Extraction finished but $lib is missing; the SDK layout may have changed."
}

Write-Host "Done. Build live capture with:  cargo build --release --features live"
