$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$agent = Join-Path $root "build\agent\Release\labagent.exe"
$admin = Join-Path $root "build\admin\Release\labadmin.exe"
$policy = Join-Path $root "policies\default.json"

if (-not (Test-Path $agent)) {
    Write-Host "Execute primeiro: powershell scripts/build.ps1"
    exit 1
}

Write-Host "=== Demo LabOrchestrator ==="
Write-Host "1. Inicie o agente em outro terminal:"
Write-Host "   $agent --key keys\shared.key"
Write-Host ""
Write-Host "2. Descobrir agentes:"
Write-Host "   $admin discover"
Write-Host ""
Write-Host "3. Enviar politica:"
Write-Host "   $admin push <AGENT_ID> $policy"
Write-Host ""
Write-Host "4. Trocar perfil:"
Write-Host "   $admin switch <AGENT_ID> Programacao"
Write-Host ""
Write-Host "5. Disparar reset:"
Write-Host "   $admin reset <AGENT_ID>"
