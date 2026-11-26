param(
  [Parameter(Mandatory = $true)][string]$List,
  [int]$Limit = 0,
  [int]$Concurrency = 4,
  [string]$Text = "templates/newsletter.txt",
  [string]$Html = "templates/newsletter.html",
  [string]$Subject = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$nodeArgs = @("src/cli.js", "send", "--list", $List, "--text", $Text, "--html", $Html, "--concurrency", $Concurrency, "--yes")
if ($Limit -gt 0) { $nodeArgs += @("--limit", $Limit) }
if ($Subject) { $nodeArgs += @("--subject", $Subject) }

Write-Host "Running: node $($nodeArgs -join ' ')" -ForegroundColor DarkGray
node @nodeArgs
