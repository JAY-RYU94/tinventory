#Requires -Version 5.1
<#
.SYNOPSIS
  swinventory Windows 에이전트 설치(관리자 PowerShell). 에이전트 자체는 저권한 계정(LOCAL SERVICE)의 예약 작업으로 실행된다.

.EXAMPLE
  .\install.ps1 -ServerUrl https://inventory.example.com -TokenFile .\ingest-token -CaFile .\ca.pem -ExePath .\swinventory-agent.exe
  .\install.ps1 -Uninstall            # 제거(설정·스풀은 남김)   .\install.ps1 -Uninstall -Purge   # 설정·스풀까지 삭제

.EXAMPLE
  # 서버에서 내려받아 설치(화면의 "서버 등록"이 이 명령을 만들어 준다). 토큰은 환경변수 SWINV_TOKEN 으로 전달한다.
  $env:SWINV_TOKEN='...'; .\install.ps1 -ServerUrl https://inventory.example.com -AgentUrl https://inventory.example.com/download/swinventory-agent-win-x64.exe -Sha256 <해시>
  .\install.ps1 -DownloadOnly -AgentUrl <URL> -Sha256 <해시> [-OutFile .\swinventory-agent.exe]   # 다운로드·해시 검증만(관리자 불필요)

.DESCRIPTION
  하는 일: 파일 배치(Program Files) → 데이터 폴더(ProgramData)와 ACL(토큰·설정은 SYSTEM/Administrators 쓰기, 에이전트 계정은 읽기만,
  스풀만 쓰기) → agent.json → 예약 작업(기본 60분마다, 무작위 지연) → 첫 수집 검증. 멱등: 다시 실행하면 갱신한다.
  종료 코드: 0 성공 · 1 설치/수집 실패 · 2 인자 오류 · 3 설치는 끝났지만 서버에 첫 전송을 확인하지 못함(스풀 보관)
#>
[CmdletBinding()]
param(
    [string]$ServerUrl, [string]$TokenFile, [string]$Token, [string]$CaFile, [string]$ClientCert, [string]$ClientKey,
    [string]$ExePath, [int]$IntervalMinutes = 60, [switch]$AllowInsecureHttp, [switch]$NoTask,
    [switch]$Uninstall, [switch]$Purge,
    [string]$AgentUrl, [string]$Sha256, [switch]$DownloadOnly, [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


function Fail([string]$Message, [int]$Code = 1) { [Console]::Error.WriteLine("ERROR: $Message"); exit $Code }
function Info([string]$Message) { Write-Host "==> $Message" }

# 서버에서 에이전트를 내려받아 해시를 확인한다. 해시는 관리자 화면이 만든 명령에 박혀 있다 — 다르면 설치하지 않고 파일도 남기지 않는다.
function Get-VerifiedAgent {
    if (-not $Sha256) { Fail '-AgentUrl 에는 -Sha256 이 필요하다(다운로드 무결성을 고정한다)' 2 }
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { Fail '-Sha256 은 16진수 64자여야 한다' 2 }
    if ($AgentUrl -notmatch '^https?://') { Fail '-AgentUrl 은 http(s):// 형식이어야 한다' 2 }
    if ($AgentUrl -match '^http://' -and -not $AllowInsecureHttp) { Fail '에이전트 URL 은 https 만 허용한다(실험실은 -AllowInsecureHttp)' 2 }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('swinv-agent-' + [Guid]::NewGuid().ToString('N') + '.exe')
    try { Invoke-WebRequest -UseBasicParsing -Uri $AgentUrl -OutFile $tmp }
    catch { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; Fail ("에이전트를 내려받지 못했다: $AgentUrl (" + $_.Exception.GetType().Name + ')') 1 }
    $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Sha256.ToLowerInvariant()) {
        Remove-Item $tmp -Force
        Fail "에이전트 해시 불일치 — 설치하지 않는다 (기대 $($Sha256.ToLowerInvariant()), 실제 $actual). 서버의 파일이 바뀌었으면 화면에서 명령을 다시 만든다." 1
    }
    return $tmp
}

if ($DownloadOnly) {   # 관리자·Windows 가 아니어도 다운로드와 해시 검증만(사전 배치·진단용)
    if (-not $AgentUrl) { Fail '-DownloadOnly 에는 -AgentUrl 이 필요하다' 2 }
    $downloaded = Get-VerifiedAgent
    if ($OutFile) { Move-Item -Path $downloaded -Destination $OutFile -Force; $downloaded = $OutFile }
    Write-Output $downloaded
    exit 0
}

# Windows 전용 경로·계정(위의 -DownloadOnly 는 Windows 가 아니어도 동작해야 하므로 그 뒤에 둔다)
$InstallDir = Join-Path $env:ProgramFiles 'swinventory'
$DataDir = Join-Path $env:ProgramData 'swinventory'
$Exe = Join-Path $InstallDir 'swinventory-agent.exe'
$TaskName = 'swinventory-agent'
$AgentAccount = 'NT AUTHORITY\LOCAL SERVICE'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail '관리자 권한 PowerShell 로 실행해야 한다(설치만 관리자, 에이전트는 LOCAL SERVICE 로 실행된다)' 2
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    if ($Purge -and (Test-Path $DataDir)) { Remove-Item $DataDir -Recurse -Force }
    Info ('제거 완료' + $(if ($Purge) { ' (설정·스풀 포함)' } else { ' (설정과 스풀은 남겼다: -Purge 로 삭제)' }))
    exit 0
}

# --- 인자 검증 --------------------------------------------------------------
if (-not $ServerUrl) { Fail '-ServerUrl 이 필요하다' 2 }
if ($ServerUrl -notmatch '^https://') {
    if ($ServerUrl -match '^http://' -and $AllowInsecureHttp) { Write-Warning '평문 http 는 실험실 전용이다' }
    else { Fail 'https 만 허용한다(실험실은 -AllowInsecureHttp)' 2 }
}
if (-not $Token -and -not $TokenFile -and $env:SWINV_TOKEN) { $Token = $env:SWINV_TOKEN }   # 환경변수는 다른 프로세스의 명령줄에 보이지 않는다
Remove-Item Env:SWINV_TOKEN -ErrorAction SilentlyContinue                                  # 하위 프로세스(첫 수집 검증)로 새지 않게
if (-not $Token -and -not $TokenFile) { Fail '토큰이 필요하다: 환경변수 SWINV_TOKEN(권장)·-TokenFile·-Token' 2 }
if ($TokenFile -and -not (Test-Path $TokenFile)) { Fail "-TokenFile 을 읽을 수 없다: $TokenFile" 2 }
if ($ClientCert -and -not $ClientKey) { Fail '-ClientCert 는 -ClientKey 와 함께 지정한다' 2 }
if ($IntervalMinutes -lt 5) { Fail '-IntervalMinutes 는 5 이상이어야 한다' 2 }
$Downloaded = $null
if ($AgentUrl) {
    if ($ExePath) { Fail '-ExePath 와 -AgentUrl 은 함께 쓸 수 없다' 2 }
    Info "에이전트 다운로드: $AgentUrl"
    $Downloaded = Get-VerifiedAgent
    $ExePath = $Downloaded
    Info 'sha256 일치 확인'
}
if (-not $ExePath) { $ExePath = Join-Path $PSScriptRoot 'swinventory-agent.exe' }
if (-not (Test-Path $ExePath)) { Fail "swinventory-agent.exe 를 찾지 못했다(-ExePath 로 지정, 빌드: windows-agent/build.sh publish): $ExePath" 2 }

# --- ACL: 토큰·설정은 관리자만 쓰고 에이전트 계정은 읽기만, 스풀만 쓰기 ---------------
function Set-PrivateAcl([string]$Path, [string[]]$Modify = @(), [string[]]$Read = @()) {
    $acl = Get-Acl -Path $Path
    $acl.SetAccessRuleProtection($true, $false)                       # 상속을 끊고
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }   # 기존 규칙을 모두 지운다
    $isDir = (Get-Item -Path $Path).PSIsContainer
    $inherit = if ($isDir) { 'ContainerInherit,ObjectInherit' } else { 'None' }
    function Add-Rule([string]$Identity, [string]$Rights) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $inherit, 'None', 'Allow')))
    }
    foreach ($id in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators') { Add-Rule $id 'FullControl' }
    foreach ($id in $Modify) { Add-Rule $id 'Modify' }
    foreach ($id in $Read) { Add-Rule $id 'ReadAndExecute' }
    Set-Acl -Path $Path -AclObject $acl
}

Info "에이전트 설치: $Exe"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path $ExePath -Destination $Exe -Force
if ($Downloaded) { Remove-Item -Path $Downloaded -Force -ErrorAction SilentlyContinue }

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$SpoolDir = Join-Path $DataDir 'spool'
New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null
Set-PrivateAcl -Path $DataDir -Read @($AgentAccount)
Set-PrivateAcl -Path $SpoolDir -Modify @($AgentAccount)

$TokenPath = Join-Path $DataDir 'token'
if ($TokenFile) { Copy-Item -Path $TokenFile -Destination $TokenPath -Force }
else { [IO.File]::WriteAllText($TokenPath, $Token, (New-Object Text.UTF8Encoding $false)) }
Set-PrivateAcl -Path $TokenPath -Read @($AgentAccount)

$config = [ordered]@{ server_url = $ServerUrl; token_file = $TokenPath; spool_path = $SpoolDir }
foreach ($pair in @(@('ca_file', $CaFile, 'ca.pem'), @('client_cert', $ClientCert, 'client.pem'), @('client_key', $ClientKey, 'client.key'))) {
    if ($pair[1]) {
        $target = Join-Path $DataDir $pair[2]
        Copy-Item -Path $pair[1] -Destination $target -Force
        Set-PrivateAcl -Path $target -Read @($AgentAccount)
        $config[$pair[0]] = $target
    }
}
if ($AllowInsecureHttp) { $config['allow_insecure_http'] = $true }
$ConfigPath = Join-Path $DataDir 'agent.json'
[IO.File]::WriteAllText($ConfigPath, ($config | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
Set-PrivateAcl -Path $ConfigPath -Read @($AgentAccount)

# --- 예약 작업(저권한 서비스 계정) -------------------------------------------------
if (-not $NoTask) {
    Info "예약 작업 등록: $TaskName ($IntervalMinutes 분마다, 계정 $AgentAccount)"
    $delay = [Math]::Min(10, [Math]::Max(1, [int]($IntervalMinutes / 6)))
    $action = New-ScheduledTaskAction -Execute $Exe -Argument ('collect --config "{0}"' -f $ConfigPath)
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650) -RandomDelay (New-TimeSpan -Minutes $delay)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $AgentAccount -LogonType ServiceAccount -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable `
        -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings `
        -Description 'swinventory: 설치 소프트웨어·커널·IP·열린 포트 수집' -Force | Out-Null
}

# --- 첫 수집 검증 ------------------------------------------------------------
Info '수집 검증(print)'
$json = & $Exe print --config $ConfigPath
if ($LASTEXITCODE -ne 0) { Fail "수집이 실패했다(종료 코드 $LASTEXITCODE). 위 메시지를 확인한다. 설치 파일은 배치됐다." 1 }
$snapshot = $json | ConvertFrom-Json
foreach ($name in $snapshot.errors.PSObject.Properties.Name) { Write-Warning "수집기 실패: $name : $($snapshot.errors.$name)" }

if (-not $NoTask) {
    Info '예약 작업을 지금 실행해 서버 전송 확인(저권한 계정으로)'
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(180)
    do { Start-Sleep -Seconds 2 } while ((Get-ScheduledTask -TaskName $TaskName).State -eq 'Running' -and (Get-Date) -lt $deadline)
    $result = (Get-ScheduledTaskInfo -TaskName $TaskName).LastTaskResult
    if ($result -ne 0) { Fail "예약 작업이 실패했다(결과 코드 $result — 1=수집/전송 실패, 2=설정 오류, 4=서버 거절). 이벤트 뷰어/설정을 확인한다." 1 }
    $pending = @(Get-ChildItem -Path $SpoolDir -Filter '*.json' -ErrorAction SilentlyContinue).Count
    if ($pending -gt 0) {
        Fail '설치는 끝났지만 서버에 전송하지 못해 스풀에 보관됐다 — 서버 주소·토큰·방화벽·CA 를 확인한다(복구 후 자동 재전송됨).' 3
    }
}
Info '설치 완료. 서버에 첫 스냅샷을 전달했다.'
