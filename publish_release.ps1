# publish_release.ps1 -- push the project folder to GitHub and tag it.
# Usage (PowerShell, from the project root where run_v2.py lives):
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\publish_release.ps1 -Remote https://github.com/<user>/<repo>.git
# Prerequisite: an EMPTY public repository created on github.com (no README / .gitignore / license).
param(
  [Parameter(Mandatory = $true)] [string] $Remote,
  [string] $Tag = "v1.0"
)
$ErrorActionPreference = "Stop"

# 0. Secret scan on OUR files only (skip .venv, node_modules, .git, .cache)
$skip = '\\(\.venv|venv|node_modules|\.git|\.cache)\\'
$hits = Get-ChildItem -Recurse -Include *.py,*.json,*.md,*.js,*.txt,*.ps1 -File |
        Where-Object { $_.FullName -notmatch $skip } |
        Select-String -Pattern 'sk-[A-Za-z0-9_-]{20,}' -List
if ($hits) {
  $hits | ForEach-Object { Write-Host "Possible API key: $($_.Path):$($_.LineNumber)" }
  throw "Remove the key(s) above and run again."
}

# 1. README
if (Test-Path README_RELEASE.md) { Move-Item -Force README_RELEASE.md README.md }

# 2. Safety: make sure the virtualenv is ignored before the first add
$gi = Get-Content .gitignore -Raw
if ($gi -notmatch '(?m)^\.venv/') { Add-Content .gitignore "`n.venv/`nvenv/`n" }

# 3. git init + commit
if (-not (Test-Path .git)) { git init -b main | Out-Null }
git add -A
$staged = git diff --cached --name-only
if ($staged -match '^\.venv/') { throw ".venv is staged; check .gitignore" }
git commit -m "Artifact release: generator, payload corpus, harness, per-item records, paper sources" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "(nothing new to commit - using existing commit)" }

# 4. remote + push
$existing = git remote 2>$null
if ($existing -contains "origin") { git remote set-url origin $Remote } else { git remote add origin $Remote }
git push -u origin main

# 5. tag
git tag -a $Tag -m "ICCA 2026 submission artifact" 2>$null
git push origin $Tag

# 6. values for the paper
$hash = git rev-parse HEAD
$short = git rev-parse --short=12 HEAD
$url = $Remote -replace '\.git$', ''
Write-Host ""
Write-Host "================ values for the paper ================"
Write-Host "URL   : $url"
Write-Host "Tag   : $Tag"
Write-Host "Commit: $hash  (short: $short)"
Write-Host "======================================================"
Write-Host "Send these three lines back; they go into content_v12.js, content_v13_short.js and MANIFEST.json."
