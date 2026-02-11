param(
    [string]$SourcePath,
    [string]$DestinationPath,
    [switch]$CleanDestination
)

$ErrorActionPreference = 'Stop'

function Resolve-SourcePath {
    param([string]$Requested)

    if ($Requested -and $Requested.Trim().Length -gt 0) {
        return (Resolve-Path -LiteralPath $Requested).Path
    }

    if ($env:WIREGUARD_WINDOWS_SOURCE -and $env:WIREGUARD_WINDOWS_SOURCE.Trim().Length -gt 0) {
        return (Resolve-Path -LiteralPath $env:WIREGUARD_WINDOWS_SOURCE).Path
    }

    $defaultInstall = 'C:\Program Files\WireGuard'
    if (Test-Path -LiteralPath $defaultInstall) {
        return (Resolve-Path -LiteralPath $defaultInstall).Path
    }

    throw "WireGuard source path not found. Pass -SourcePath, set WIREGUARD_WINDOWS_SOURCE, or install WireGuard in '$defaultInstall'."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$targetRoot = if ($DestinationPath -and $DestinationPath.Trim().Length -gt 0) {
    $DestinationPath
} else {
    Join-Path $repoRoot 'clients\windows-desktop\wg-tools'
}

$sourceRoot = Resolve-SourcePath -Requested $SourcePath
$targetRoot = [System.IO.Path]::GetFullPath($targetRoot)

Write-Host "Staging WireGuard runtime"
Write-Host "  Source      : $sourceRoot"
Write-Host "  Destination : $targetRoot"

if ($CleanDestination -and (Test-Path -LiteralPath $targetRoot)) {
    Write-Host "Cleaning destination directory"
    Get-ChildItem -LiteralPath $targetRoot -Force | Remove-Item -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null

Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $targetRoot -Recurse -Force

$wireguardExe = Join-Path $targetRoot 'wireguard.exe'
if (-not (Test-Path -LiteralPath $wireguardExe)) {
    throw "Staging completed but '$wireguardExe' is missing. Source does not look like a WireGuard runtime directory."
}

Write-Host "WireGuard runtime staged successfully"
Write-Host "  Required binary found: $wireguardExe"
