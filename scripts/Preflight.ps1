param(
  [string]$Text = "templates/newsletter.txt",
  [string]$Html = "templates/newsletter.html",
  [string]$Subject = "",
  [string]$List = "config/recipients.example.csv",
  [string]$Ip = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$policy = Get-Content "config/policy.json" -Raw | ConvertFrom-Json
if (-not $Subject) { $Subject = $policy.subject }

Write-Host "== 1. Spam score ==" -ForegroundColor Cyan
node src/cli.js score --text $Text --html $Html --subject $Subject

Write-Host "`n== 2. DNS / reputation ==" -ForegroundColor Cyan
if ($Ip) { node src/cli.js dnscheck --domain $policy.from_domain --ip $Ip }
else { node src/cli.js dnscheck --domain $policy.from_domain }

Write-Host "`n== 3. MIME + DKIM dry run (first recipient) ==" -ForegroundColor Cyan
node src/cli.js send --list $List --text $Text --html $Html --subject $Subject --dry-run --yes

Write-Host "`nPreflight done. If score < 2.5, DNS grade A/B and dry-run looks right, send a seed test next." -ForegroundColor Yellow
