param(
  [string]$Ip = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$policy = Get-Content "config/policy.json" -Raw | ConvertFrom-Json

Write-Host "== Relay pool ==" -ForegroundColor Cyan
node src/cli.js pool

Write-Host "`n== Egress / block diagnosis ==" -ForegroundColor Cyan
node src/cli.js diagnose

Write-Host "`n== Queue ==" -ForegroundColor Cyan
node src/cli.js queue stats

Write-Host "`n== DNS / reputation ==" -ForegroundColor Cyan
if ($Ip) { node src/cli.js dnscheck --domain $policy.from_domain --ip $Ip }
else { node src/cli.js dnscheck --domain $policy.from_domain }

Write-Host "`n== Last probe ==" -ForegroundColor Cyan
$probe = Get-ChildItem "reports/probe-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($probe) {
  $data = Get-Content $probe.FullName -Raw | ConvertFrom-Json
  $data.reports | ForEach-Object { "{0,-8} grade={1} findings={2}" -f $_.target, $_.grade, $_.findings.Count }
}
else { Write-Host "no probe report yet (run: node src/cli.js probe --target gmail,outlook)" }
