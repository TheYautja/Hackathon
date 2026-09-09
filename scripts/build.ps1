$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$build = Join-Path $root "build"

if (-not (Test-Path (Join-Path $root "keys\shared.key"))) {
    & (Join-Path $root "scripts\genkeys.ps1")
}

New-Item -ItemType Directory -Force -Path $build | Out-Null
Set-Location $build

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    $vsCmake = "C:\Program Files\Microsoft Visual Studio\18\Insiders\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $vsCmake) { $cmake = $vsCmake } else { throw "CMake nao encontrado. Instale CMake ou Visual Studio com C++." }
} else {
    $cmake = $cmake.Source
}

& $cmake .. -DCMAKE_BUILD_TYPE=Release
& $cmake --build . --config Release
if ($LASTEXITCODE -ne 0) { throw "Build falhou com codigo $LASTEXITCODE" }

$agentExe = Join-Path $build "agent\Release\labagent.exe"
$adminExe = Join-Path $build "admin\Release\labadmin.exe"
if (-not (Test-Path $agentExe) -or -not (Test-Path $adminExe)) {
    throw "Binarios nao encontrados apos build."
}

Write-Host ""
Write-Host "Binarios:"
Write-Host "  $agentExe"
Write-Host "  $adminExe"
