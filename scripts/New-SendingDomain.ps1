param(
  [Parameter(Mandatory = $true)][string]$Domain,
  [string]$Selector = "s1",
  [string]$Ip = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== 1. DKIM key for $Domain (selector $Selector) ==" -ForegroundColor Cyan
node src/cli.js keys --domain $Domain --selector $Selector
if ($LASTEXITCODE -ne 0) { throw "keys failed" }

Write-Host "`n== 2. DNS audit ==" -ForegroundColor Cyan
if ($Ip) { node src/cli.js dnscheck --domain $Domain --ip $Ip }
else { node src/cli.js dnscheck --domain $Domain }

Write-Host "`n== 3. Records to publish ==" -ForegroundColor Cyan
node src/cli.js dns-records --domain $Domain

Write-Host "`nNext: publish records, wait for TTL, then re-run dnscheck until grade A/B." -ForegroundColor Yellow
