param(
  [int]$Connections = 8,
  [int]$Rcpt = 5
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "== Egress / reputation / per-receiver block ==" -ForegroundColor Cyan
node src/cli.js diagnose

Write-Host "`n== Gmail SMTP command-rate ==" -ForegroundColor Cyan
node src/cli.js ratelimit --target gmail.com --connections $Connections --rcpt $Rcpt

Write-Host "`nReports written to reports/" -ForegroundColor Yellow
