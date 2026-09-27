<#
.SYNOPSIS
    Build (or rebuild) the ASKQ MySQL databases: schema, deterministic seed
    data, least-privilege accounts, and verification.

.DESCRIPTION
    Steps, all in ONE mysql session (so at most one password prompt):
      [-Reset] drop askq_university and askq_system (only those two)
      schema\*.sql              create databases, tables, indexes, views
      seed\generated\0*.sql     reference data, synthetic population, security-demo cohorts
      accounts                  create/update askq_reader and askq_app, then accounts\grants.sql
      validation\verify_database.sql + validation\verify_security_cohorts.sql
    Then, if accounts were set up, tools\verify_accounts.py logs in AS each
    account to prove what it can and cannot do.

    Admin connection: the MySQL login path named by -LoginPath (default
    'askq_admin'), created once by YOU with:
        mysql_config_editor set --login-path=askq_admin --host=localhost --user=root --password
    Without it, mysql prompts for the root password.

    Account passwords come from DB_READER_PASSWORD / DB_APP_PASSWORD in the
    git-ignored C:\ASKQ\.env. They are sent to mysql through stdin only: never
    printed, logged, or written to any file by this script.

    Host convention: the application accounts exist only as
    'askq_reader'@'127.0.0.1' and 'askq_app'@'127.0.0.1', and DB_HOST must be
    127.0.0.1 (checked below). The admin connection is separate and keeps your
    existing root@localhost account.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\database\setup_db.ps1
.EXAMPLE
    .\database\setup_db.ps1 -Reset          # drop and rebuild (asks you to type RESET)
.EXAMPLE
    .\database\setup_db.ps1 -AccountsOnly   # only (re)create accounts and grants
#>
[CmdletBinding()]
param(
    # Drop askq_university and askq_system first (asks for confirmation).
    [switch]$Reset,
    # Skip the -Reset confirmation prompt.
    [switch]$Force,
    # Build the databases without creating/updating the MySQL accounts.
    [switch]$SkipAccounts,
    # Only create/update the accounts and re-apply grants (databases must exist).
    [switch]$AccountsOnly,
    [string]$LoginPath = 'askq_admin',
    # Seed for the synthetic data; omit to use the generator's fixed default.
    [int]$Seed
)

$ErrorActionPreference = 'Stop'
$DbDir = $PSScriptRoot
$Root = Split-Path -Parent $DbDir
$Python = Join-Path $Root 'backend\.venv\Scripts\python.exe'
$EnvFile = Join-Path $Root '.env'
$MinPasswordLength = 16
# Excludes quotes, backslash, '#', '$' and spaces so the value means the same
# thing to .env parsers, PowerShell and SQL, and needs no escaping.
$PasswordPattern = '^[A-Za-z0-9._~!@%^*+=:,-]+$'
$AccountHost = '127.0.0.1'
$Accounts = @(
    @{ User = 'askq_reader'; EnvUser = 'DB_READER_USER'; EnvPassword = 'DB_READER_PASSWORD' },
    @{ User = 'askq_app'; EnvUser = 'DB_APP_USER'; EnvPassword = 'DB_APP_PASSWORD' }
)

if ($AccountsOnly -and ($SkipAccounts -or $Reset)) {
    throw '-AccountsOnly cannot be combined with -SkipAccounts or -Reset.'
}

function ConvertTo-SqlPath([string]$Path) { $Path -replace '\\', '/' }

function Get-DotEnvValue([string]$Name) {
    if (-not (Test-Path -LiteralPath $EnvFile)) { return $null }
    foreach ($line in Get-Content -LiteralPath $EnvFile -Encoding UTF8) {
        if ($line -match '^\s*#' -or $line -notmatch '=') { continue }
        $key, $value = $line -split '=', 2
        if ($key.Trim() -ceq $Name) { return $value.Trim() }
    }
    return $null
}

# ---------- 1. Account passwords (checked before anything touches MySQL) ----------
$accountSql = @()
if (-not $SkipAccounts) {
    $problems = @()
    $dbHost = Get-DotEnvValue 'DB_HOST'
    if ($dbHost -and $dbHost -cne $AccountHost) {
        $problems += "DB_HOST is '$dbHost' but must be $AccountHost (the accounts are created @'$AccountHost')"
    }
    $seen = @{}
    foreach ($a in $Accounts) {
        $user = Get-DotEnvValue $a.EnvUser
        if ($user -and $user -cne $a.User) {
            $problems += "$($a.EnvUser) is '$user' but must be '$($a.User)' (grants.sql uses that name)"
        }
        $pw = Get-DotEnvValue $a.EnvPassword
        if ([string]::IsNullOrEmpty($pw)) { $problems += "$($a.EnvPassword) is not set" }
        elseif ($pw -like 'change-me*') { $problems += "$($a.EnvPassword) still has the placeholder from .env.example" }
        elseif ($pw.Length -lt $MinPasswordLength) { $problems += "$($a.EnvPassword) is shorter than $MinPasswordLength characters" }
        elseif ($pw -cnotmatch $PasswordPattern) { $problems += "$($a.EnvPassword) contains characters other than A-Z a-z 0-9 . _ ~ ! @ % ^ * + = : , -" }
        elseif ($seen.ContainsKey($pw)) { $problems += "$($a.EnvPassword) must differ from $($seen[$pw])" }
        else {
            $seen[$pw] = $a.EnvPassword
            $accountSql += "CREATE USER IF NOT EXISTS '$($a.User)'@'$AccountHost' IDENTIFIED BY '$pw' WITH MAX_USER_CONNECTIONS 20;"
            $accountSql += "ALTER USER '$($a.User)'@'$AccountHost' IDENTIFIED BY '$pw' WITH MAX_USER_CONNECTIONS 20;"
        }
        $pw = $null
    }
    if ($problems) {
        Write-Host 'Cannot create the ASKQ MySQL accounts yet:' -ForegroundColor Yellow
        $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        Write-Host "Set them in $EnvFile (copy .env.example if it does not exist; see database\README.md)."
        Write-Host 'Or build the databases without accounts for now:  .\database\setup_db.ps1 -SkipAccounts'
        exit 2
    }
}

# ---------- 2. Admin connection ----------
$mysql = (Get-Command mysql.exe -ErrorAction Stop).Source
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$loginPathConfigured = [bool](& mysql_config_editor print "--login-path=$LoginPath" 2>$null)
$ErrorActionPreference = $previousPreference
if ($loginPathConfigured) {
    $adminArgs = @("--login-path=$LoginPath")
    Write-Host "Admin connection: MySQL login path '$LoginPath'"
} else {
    $adminArgs = @('--host=localhost', '--user=root', '--password')
    Write-Host "Login path '$LoginPath' not found: mysql will ask for the root password once."
}

# ---------- 3. Reset confirmation ----------
if ($Reset -and -not $Force) {
    Write-Host 'This DROPS askq_university and askq_system (all ASKQ data, including query history).' -ForegroundColor Yellow
    if ((Read-Host 'Type RESET to continue') -cne 'RESET') { Write-Host 'Aborted; nothing changed.'; exit 1 }
}

# ---------- 4. Generate seed SQL ----------
$generated = Join-Path $DbDir 'seed\generated'
if (-not $AccountsOnly) {
    if (-not (Test-Path -LiteralPath $Python)) { throw "Backend venv not found ($Python). Run backend\setup.ps1 first." }
    $genArgs = @((Join-Path $DbDir 'seed\generate_seed.py'))
    if ($PSBoundParameters.ContainsKey('Seed')) { $genArgs += @('--seed', "$Seed") }
    & $Python @genArgs
    if ($LASTEXITCODE -ne 0) { throw 'Seed generation failed.' }
    foreach ($name in '01_reference_data.sql', '02_synthetic_data.sql', '03_security_demo_data.sql') {
        if (-not (Test-Path -LiteralPath (Join-Path $generated $name))) { throw "Generator did not produce $name." }
    }
}

# ---------- 5. One mysql session ----------
$plan = @(
    "SET SESSION sql_mode = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';"
)
if ($Reset) { $plan += 'SOURCE ' + (ConvertTo-SqlPath (Join-Path $DbDir 'reset\drop_askq_databases.sql')) }
if (-not $AccountsOnly) {
    Get-ChildItem -LiteralPath (Join-Path $DbDir 'schema') -Filter '*.sql' | Sort-Object Name |
        ForEach-Object { $plan += 'SOURCE ' + (ConvertTo-SqlPath $_.FullName) }
    foreach ($name in '01_reference_data.sql', '02_synthetic_data.sql', '03_security_demo_data.sql') {
        $plan += 'SOURCE ' + (ConvertTo-SqlPath (Join-Path $generated $name))
    }
}
if ($accountSql) {
    $plan += $accountSql
    $plan += 'SOURCE ' + (ConvertTo-SqlPath (Join-Path $DbDir 'accounts\grants.sql'))
}
$plan += 'SOURCE ' + (ConvertTo-SqlPath (Join-Path $DbDir 'validation\verify_database.sql'))
# Committed, seed-independent file (no dependency on generated output).
$plan += 'SOURCE ' + (ConvertTo-SqlPath (Join-Path $DbDir 'validation\verify_security_cohorts.sql'))

Write-Host 'Running MySQL steps...'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
($plan -join "`n") + "`n" | & $mysql @adminArgs --default-character-set=utf8mb4 --table
$exitCode = $LASTEXITCODE
$plan = $null
$accountSql = $null
if ($exitCode -ne 0) {
    Write-Host "MySQL step failed (exit code $exitCode); see the error above." -ForegroundColor Red
    Write-Host 'If it says the database already exists, rebuild with:  .\database\setup_db.ps1 -Reset'
    exit $exitCode
}

# ---------- 6. Prove the accounts' privileges by logging in as them ----------
if (-not $SkipAccounts) {
    & $Python (Join-Path $DbDir 'tools\verify_accounts.py')
    if ($LASTEXITCODE -ne 0) { throw 'Account privilege verification failed.' }
}

Write-Host 'ASKQ database setup complete.' -ForegroundColor Green
