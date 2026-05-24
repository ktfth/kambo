# =============================================================================
# Kambo Social Media Poster — Setup para Windows
# Execute no PowerShell como Administrador:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\setup-windows.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗"
Write-Host "║  🐸 Kambo Social Media Poster — Setup Windows               ║"
Write-Host "╚══════════════════════════════════════════════════════════════╝"
Write-Host ""

# ─────────────────────────────────────────────────
# 1. Verificar Python
# ─────────────────────────────────────────────────
Write-Host "🔍 Verificando Python..." -ForegroundColor Cyan

$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $version = & $cmd --version 2>&1
        if ($version -match "Python 3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) {
                $pythonCmd = $cmd
                Write-Host "✅ $version encontrado ($cmd)" -ForegroundColor Green
                break
            } else {
                Write-Host "⚠️  $version encontrado, mas é necessário 3.11+" -ForegroundColor Yellow
            }
        }
    } catch { }
}

if (-not $pythonCmd) {
    Write-Host "❌ Python 3.11+ não encontrado." -ForegroundColor Red
    Write-Host "   Baixe em: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "   Marque 'Add Python to PATH' durante a instalação."
    exit 1
}

# ─────────────────────────────────────────────────
# 2. Verificar Google Chrome
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "🔍 Verificando Google Chrome..." -ForegroundColor Cyan

$chromePaths = @(
    "$env:PROGRAMFILES\Google\Chrome\Application\chrome.exe",
    "$env:PROGRAMFILES(X86)\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)

$chromeFound = $false
foreach ($path in $chromePaths) {
    if (Test-Path $path) {
        Write-Host "✅ Chrome encontrado: $path" -ForegroundColor Green
        $chromeFound = $true
        break
    }
}

if (-not $chromeFound) {
    Write-Host "⚠️  Google Chrome não encontrado." -ForegroundColor Yellow
    Write-Host "   Baixe em: https://www.google.com/chrome/"
    Write-Host "   (necessário para o modo browser)"
}

# ─────────────────────────────────────────────────
# 3. Instalar dependências Python
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "📦 Instalando dependências Python..." -ForegroundColor Cyan

$reqFile = Join-Path $ScriptDir "requirements-social.txt"
& $pythonCmd -m pip install --upgrade pip --quiet
& $pythonCmd -m pip install -r $reqFile

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Falha ao instalar dependências." -ForegroundColor Red
    exit 1
}
Write-Host "✅ Dependências instaladas." -ForegroundColor Green

# ─────────────────────────────────────────────────
# 4. Instalar o Chrome para Playwright
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "🌐 Instalando driver Chrome do Playwright..." -ForegroundColor Cyan
& $pythonCmd -m playwright install chrome

if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Falha ao instalar Chrome do Playwright." -ForegroundColor Yellow
    Write-Host "   Tente manualmente: playwright install chrome"
} else {
    Write-Host "✅ Chrome do Playwright instalado." -ForegroundColor Green
}

# ─────────────────────────────────────────────────
# 5. Criar .env se não existir
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "⚙️  Configurando .env..." -ForegroundColor Cyan

$envFile = Join-Path $ScriptDir ".env"
$envExample = Join-Path $ScriptDir ".env.example"

if (-not (Test-Path $envFile)) {
    Copy-Item $envExample $envFile
    Write-Host "✅ .env criado a partir do .env.example" -ForegroundColor Green
    Write-Host "   Edite o arquivo .env para configurar suas credenciais:"
    Write-Host "   notepad `"$envFile`""
} else {
    Write-Host "ℹ️  .env já existe. Mantendo configurações atuais." -ForegroundColor Gray
}

# ─────────────────────────────────────────────────
# 6. Detectar perfil do Chrome
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "🔍 Detectando perfil do Chrome..." -ForegroundColor Cyan

$chromeProfileDir = "$env:LOCALAPPDATA\Google\Chrome\User Data"
if (Test-Path $chromeProfileDir) {
    Write-Host "✅ Perfil encontrado: $chromeProfileDir" -ForegroundColor Green

    # Atualiza .env com o caminho do perfil
    $envContent = Get-Content $envFile -Raw
    if ($envContent -match "CHROME_PROFILE_DIR=`$") {
        $envContent = $envContent -replace "CHROME_PROFILE_DIR=", "CHROME_PROFILE_DIR=$chromeProfileDir"
        Set-Content $envFile $envContent -NoNewline
        Write-Host "   Caminho adicionado ao .env automaticamente." -ForegroundColor Green
    }
} else {
    Write-Host "⚠️  Perfil do Chrome não encontrado em $chromeProfileDir" -ForegroundColor Yellow
    Write-Host "   Defina CHROME_PROFILE_DIR no arquivo .env manualmente."
}

# ─────────────────────────────────────────────────
# 7. Instalar Task Scheduler (18h diário)
# ─────────────────────────────────────────────────
Write-Host ""
$installTask = Read-Host "⏰ Deseja agendar a publicação diária às 18h? (s/N)"

if ($installTask.ToLower() -eq "s") {
    Write-Host "📅 Instalando Task Scheduler..." -ForegroundColor Cyan

    $posterScript = Join-Path $ScriptDir "poster.py"
    $taskName = "KamboSocialPoster"
    $logFile = Join-Path $ScriptDir "post-log.jsonl"

    # Remove task existente
    schtasks /Delete /TN $taskName /F 2>$null

    # Cria a task
    $action = New-ScheduledTaskAction `
        -Execute $pythonCmd `
        -Argument "`"$posterScript`" today" `
        -WorkingDirectory $ScriptDir

    $trigger = New-ScheduledTaskTrigger -Daily -At "18:00"

    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
        -MultipleInstances IgnoreNew `
        -RunOnlyIfNetworkAvailable

    $principal = New-ScheduledTaskPrincipal `
        -UserId $env:USERNAME `
        -LogonType Interactive `
        -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Kambo — Publica post diário no Threads às 18h" `
        -Force | Out-Null

    Write-Host "✅ Task Scheduler configurado: $taskName" -ForegroundColor Green
    Write-Host "   Publica todo dia às 18h00" -ForegroundColor Green
    Write-Host ""
    Write-Host "   Comandos úteis:"
    Write-Host "   Verificar: schtasks /Query /TN $taskName /FO LIST"
    Write-Host "   Executar agora: schtasks /Run /TN $taskName"
    Write-Host "   Remover: python `"$posterScript`" schedule uninstall"
}

# ─────────────────────────────────────────────────
# 8. Teste rápido
# ─────────────────────────────────────────────────
Write-Host ""
$runTest = Read-Host "🧪 Deseja visualizar o post de hoje (dry-run)? (s/N)"

if ($runTest.ToLower() -eq "s") {
    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan
    & $pythonCmd (Join-Path $ScriptDir "poster.py") today --dry-run
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor Cyan
}

# ─────────────────────────────────────────────────
# Resumo final
# ─────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗"
Write-Host "║  ✅ Setup concluído!                                         ║"
Write-Host "╚══════════════════════════════════════════════════════════════╝"
Write-Host ""
Write-Host "Próximos passos:"
Write-Host ""
Write-Host "  1. Abra o Chrome e faça login em threads.net"
Write-Host "     (o poster usará essa sessão existente)"
Write-Host ""
Write-Host "  2. Edite o .env se necessário:"
Write-Host "     notepad `"$(Join-Path $ScriptDir ".env")`""
Write-Host ""
Write-Host "  3. Teste a publicação:"
Write-Host "     python `"$(Join-Path $ScriptDir "poster.py")`" today --dry-run"
Write-Host ""
Write-Host "  4. Para publicar de verdade:"
Write-Host "     python `"$(Join-Path $ScriptDir "poster.py")`" today"
Write-Host ""
Write-Host "  5. Ver todos os posts disponíveis:"
Write-Host "     python `"$(Join-Path $ScriptDir "poster.py")`" list"
Write-Host ""
