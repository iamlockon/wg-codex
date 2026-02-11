param(
    [string]$RuntimePath
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$runtimeRoot = if ($RuntimePath -and $RuntimePath.Trim().Length -gt 0) {
    $RuntimePath
} else {
    Join-Path $repoRoot 'clients\windows-desktop\wg-tools'
}
$runtimeRoot = [System.IO.Path]::GetFullPath($runtimeRoot)

$required = @(
    'wireguard.exe'
)

Write-Host "Verifying WireGuard runtime at: $runtimeRoot"

if (-not (Test-Path -LiteralPath $runtimeRoot)) {
    throw "Runtime path does not exist: $runtimeRoot"
}

$missing = @()
foreach ($name in $required) {
    $full = Join-Path $runtimeRoot $name
    if (-not (Test-Path -LiteralPath $full)) {
        $missing += $name
    }
}

if ($missing.Count -gt 0) {
    throw "Missing required runtime files: $($missing -join ', ')"
}

Write-Host "Runtime validation passed"
