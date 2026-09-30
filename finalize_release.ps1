# finalize_release.ps1 -- second pass: remove stale copies, add manifest/prompts/paper files, re-tag v1.0.
# Run from the project root AFTER extracting release_fix.zip over it (overwrite when asked):
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\finalize_release.ps1
param([string] $Tag = "v1.0")
$ErrorActionPreference = "Stop"

# 1. stale root-level copies of src/ modules (older versions), logs, duplicate runner
$stale = @("client.py","conditions.py","defenses.py","delivery.py","generator.py","llm.py","mock2.py",
           "payloads.py","schema.py","stats.py","synth.py","run_v2 (1).py","run.log","run_frontier.log")
foreach ($f in $stale) {
  if (Test-Path -LiteralPath $f) { git rm -q --cached -- "$f" 2>$null; Remove-Item -Force -LiteralPath $f }
}
if (Test-Path README_RELEASE.md) { Remove-Item -Force README_RELEASE.md }

# 2. stage everything else (new MANIFEST.json, paper/prompts.json, paper sources, PDFs, README, .gitignore)
git add -A
git commit -m "Release v1.0: add MANIFEST, prompts, paper sources and PDFs; remove stale root copies"

# 3. move the tag to this commit (nothing cites the old one yet)
git tag -d $Tag 2>$null | Out-Null
git push origin ":refs/tags/$Tag" 2>$null | Out-Null
git tag -a $Tag -m "ICCA 2026 submission artifact"
git push origin main
git push origin $Tag

Write-Host ""
Write-Host "Release $Tag now points at: $(git rev-parse HEAD)"
Write-Host "Check on GitHub: MANIFEST.json, paper/prompts.json, paper/PAG_paper_ICCA26_short.pdf, paper/PAG_paper_IEEE_v12.pdf"
