$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$keyDir = Join-Path $root "keys"
$keyPath = Join-Path $keyDir "shared.key"

New-Item -ItemType Directory -Force -Path $keyDir | Out-Null

$key = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
[System.IO.File]::WriteAllBytes($keyPath, $key)

Write-Host "Chave HMAC gerada: $keyPath"
Write-Host "Distribua este arquivo para todos os agentes e para o PC administrador."
