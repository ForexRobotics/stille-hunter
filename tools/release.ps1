# release.ps1  -  cut a stille-hunter release
# Bumps the version, dates the changelog, runs tests, commits (signed), tags,
# pushes, and creates a GitHub release.
#
#   powershell -ExecutionPolicy Bypass -File .\release.ps1 -Part patch
#   powershell -ExecutionPolicy Bypass -File .\release.ps1 -Part minor
#   powershell -ExecutionPolicy Bypass -File .\release.ps1 -Version 0.2.0
#   add -DryRun to preview without changing anything.
#
# Run from the repo root. ASCII-only (Windows PowerShell reads BOM-less .ps1 as cp932).

param(
    [ValidateSet("patch", "minor", "major")]
    [string]$Part = "patch",
    [string]$Version = "",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$repoSlug = "ForexRobotics/stille-hunter"
$initPath = "src/stille_hunter/__init__.py"
$changelog = "CHANGELOG.md"

function Write-NoBom($path, $text) {
    # resolve to an absolute path WITHOUT requiring the file to exist yet
    if ([System.IO.Path]::IsPathRooted($path)) { $full = $path }
    else { $full = [System.IO.Path]::Combine((Get-Location).Path, $path) }
    [System.IO.File]::WriteAllText($full, $text, (New-Object System.Text.UTF8Encoding $false))
}

if (-not (Test-Path $initPath)) {
    Write-Host "Run this from the repo root (cannot find $initPath)." -ForegroundColor Red
    exit 1
}

# --- current version --------------------------------------------------------
$initText = Get-Content $initPath -Raw
if ($initText -notmatch '__version__\s*=\s*"(\d+)\.(\d+)\.(\d+)"') {
    Write-Host "Could not find __version__ in $initPath." -ForegroundColor Red
    exit 1
}
$cur = [pscustomobject]@{ major = [int]$Matches[1]; minor = [int]$Matches[2]; patch = [int]$Matches[3] }
$curStr = "$($cur.major).$($cur.minor).$($cur.patch)"

# --- next version -----------------------------------------------------------
if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        Write-Host "-Version must look like X.Y.Z" -ForegroundColor Red; exit 1
    }
    $newStr = $Version
} else {
    switch ($Part) {
        "patch" { $newStr = "$($cur.major).$($cur.minor).$($cur.patch + 1)" }
        "minor" { $newStr = "$($cur.major).$($cur.minor + 1).0" }
        "major" { $newStr = "$($cur.major + 1).0.0" }
    }
}
$today = Get-Date -Format "yyyy-MM-dd"
Write-Host "Version: $curStr  ->  $newStr   (date $today)" -ForegroundColor Cyan

if (git tag --list "v$newStr") {
    Write-Host "Tag v$newStr already exists. Aborting." -ForegroundColor Red; exit 1
}
# Safety: if this version already has a CHANGELOG section, it was released (or
# hand-written, like the first 0.1.0). Re-cutting it would duplicate the entry.
# Tag such a version manually instead (see RELEASING.md).
if ((Get-Content $changelog -Raw) -match "## \[$([regex]::Escape($newStr))\]") {
    Write-Host "CHANGELOG already has a [$newStr] section." -ForegroundColor Red
    Write-Host "That version is already written up. To tag it, do it manually:" -ForegroundColor Yellow
    Write-Host "    git tag v$newStr; git push --tags" -ForegroundColor Yellow
    Write-Host "    gh release create v$newStr --title v$newStr --notes-file <section>" -ForegroundColor Yellow
    exit 1
}

# --- 1. bump __version__ ----------------------------------------------------
$newInit = $initText -replace '__version__\s*=\s*"\d+\.\d+\.\d+"', "__version__ = `"$newStr`""

# --- 2. rewrite CHANGELOG ---------------------------------------------------
if (-not (Test-Path $changelog)) { Write-Host "No $changelog found." -ForegroundColor Red; exit 1 }
$cl = Get-Content $changelog -Raw

# move the Unreleased notes into a dated section for the new version
$unrelHeader = "## [Unreleased]"
if ($cl -notmatch [regex]::Escape($unrelHeader)) {
    Write-Host "No '## [Unreleased]' section in $changelog." -ForegroundColor Red; exit 1
}
$newSection = "## [Unreleased]`n`n## [$newStr] - $today"
$cl2 = $cl -replace [regex]::Escape($unrelHeader), $newSection

# refresh the compare/tag links at the bottom
$base = "https://github.com/$repoSlug"
$cl2 = $cl2 -replace '(?m)^\[Unreleased\]:.*$', "[Unreleased]: $base/compare/v$newStr...HEAD"
$newLink = "[$newStr]: $base/releases/tag/v$newStr"
# insert the new tag link right after the Unreleased link line
$cl2 = $cl2 -replace '(?m)^(\[Unreleased\]:.*$)', "`$1`n$newLink"

# --- extract this version's notes for the GitHub release body ---------------
$relNotes = ""
$m = [regex]::Match($cl2, "(?s)## \[$([regex]::Escape($newStr))\] - $today`r?`n(.*?)(?=`r?`n## \[|`r?`n\[Unreleased\]:)")
if ($m.Success) { $relNotes = $m.Groups[1].Value.Trim() }
if (-not $relNotes) { $relNotes = "Release v$newStr" }

if ($DryRun) {
    Write-Host "`n--- DRY RUN: no files changed ---" -ForegroundColor Yellow
    Write-Host "would set __version__ = $newStr"
    Write-Host "would add changelog section '## [$newStr] - $today'"
    Write-Host "`nrelease notes would be:`n$relNotes" -ForegroundColor DarkGray
    exit 0
}

# --- 3. run tests before touching git ---------------------------------------
Write-Host "== running tests ==" -ForegroundColor Cyan
python -m pytest -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "Tests failed. Release aborted (no files changed yet)." -ForegroundColor Red
    exit 1
}

# write files only after tests pass
Write-NoBom $initPath $newInit
Write-NoBom $changelog $cl2

$notesFile = Join-Path $env:TEMP "stille-release-notes-$newStr.md"
Write-NoBom $notesFile $relNotes

# --- 4. commit, tag, push ---------------------------------------------------
Write-Host "== commit / tag / push ==" -ForegroundColor Cyan
git add $initPath $changelog
git commit -s -m "Release v$newStr"
git tag "v$newStr"
git push
git push --tags

# --- 5. GitHub release ------------------------------------------------------
Write-Host "== gh release ==" -ForegroundColor Cyan
gh release create "v$newStr" --repo $repoSlug --title "v$newStr" --notes-file $notesFile
Remove-Item $notesFile -ErrorAction SilentlyContinue

Write-Host "`nReleased v$newStr" -ForegroundColor Green
Write-Host "https://github.com/$repoSlug/releases/tag/v$newStr" -ForegroundColor Green
