<#
.SYNOPSIS
    Put Concord in the Start Menu, so it launches like any other application.

.DESCRIPTION
    Creates a shortcut that runs `node scripts/desktop.mjs` from this repository, carrying the
    Concord icon and starting minimised so the only window you see is the application itself.

    This writes nothing outside your own Start Menu and Desktop, installs no software, registers
    no service, and changes no system setting. Removing the shortcut removes everything it did.

.PARAMETER Desktop
    Also place a shortcut on the Desktop.

.PARAMETER InRepo
    Also write Concord.lnk into the repository itself, wired to the live model configuration in
    config/concord-live.json. This one is committed, so a clone carries it.

.PARAMETER Live
    Point the Start Menu and Desktop shortcuts at the live model too, rather than starting in the
    offline deterministic demonstration.

.PARAMETER Remove
    Delete the shortcuts this script created, including the one in the repository.

.EXAMPLE
    pwsh scripts/install-shortcut.ps1
    pwsh scripts/install-shortcut.ps1 -Desktop -Live
    pwsh scripts/install-shortcut.ps1 -InRepo
    pwsh scripts/install-shortcut.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch] $Desktop,
    [switch] $InRepo,
    [switch] $Live,
    [switch] $Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'Concord.lnk'
$desktopLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Concord.lnk'
$repoLink = Join-Path $repo 'Concord.lnk'

if ($Remove) {
    $removed = 0
    foreach ($path in @($startMenu, $desktopLink, $repoLink)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
            Write-Host "Removed $path"
            $removed++
        }
    }
    if ($removed -eq 0) { Write-Host 'No Concord shortcuts were present.' }
    return
}

# The shortcut records an exact interpreter rather than relying on PATH at click time, so it
# cannot silently start running under a different Node than the one that was checked here.
$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) {
    throw 'Concord needs Node.js 22 or newer on PATH. Install it from https://nodejs.org/ and run this again.'
}
$version = (& $node.Source --version).TrimStart('v')
if ([int]($version.Split('.')[0]) -lt 22) {
    throw "Concord needs Node.js 22 or newer; found $version at $($node.Source)."
}

$launcher = Join-Path $repo 'scripts\desktop.mjs'
if (-not (Test-Path -LiteralPath $launcher)) { throw "Cannot find $launcher" }

$icon = Join-Path $repo 'app\concord.ico'
if (-not (Test-Path -LiteralPath $icon)) {
    # The icon is committed, so this only happens in an unusual tree. Build it rather than
    # installing a shortcut that borrows the Node logo.
    & $node.Source (Join-Path $repo 'scripts\make-icon.mjs') | Out-Null
}

$liveConfig = Join-Path $repo 'config\concord-live.json'
$liveArgs = ''
if ($Live -or $InRepo) {
    if (-not (Test-Path -LiteralPath $liveConfig)) { throw "Cannot find $liveConfig" }
    $liveArgs = ' --integrations config\concord-live.json'
}

$shell = New-Object -ComObject WScript.Shell
$targets = @()
if (-not $InRepo -or $Desktop -or $Live) { $targets += $startMenu }
if ($Desktop) { $targets += $desktopLink }

foreach ($path in $targets) {
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $node.Source
    $link.Arguments = "scripts\desktop.mjs$liveArgs"
    $link.WorkingDirectory = $repo
    $link.IconLocation = "$icon,0"
    $link.Description = if ($Live) { 'Concord - live model, running locally' } else { 'Concord - policy-bound AI orchestration, running locally' }
    # 7 is minimised: the console that hosts the harness stays out of the way, and the
    # application window is the only thing on screen.
    $link.WindowStyle = 7
    $link.Save()
    Write-Host "Created $path"
}

if ($InRepo) {
    $launcher = Join-Path $repo 'Concord.cmd'
    if (-not (Test-Path -LiteralPath $launcher)) { throw "Cannot find $launcher" }
    $link = $shell.CreateShortcut($repoLink)
    # This one is committed, so it targets a file inside the repository rather than an absolute
    # interpreter path. That is the most portability a .lnk allows and it is not much: the format
    # stores absolute paths, and WScript.Shell's RelativePath does not persist (verified: the
    # HasRelativePath flag stays clear whatever order it is set in). A clone on another machine,
    # or at another path, should regenerate it with this script rather than trust the committed
    # one. Targeting Concord.cmd at least keeps the target inside the repository, so only the
    # prefix is wrong rather than the whole interpreter path.
    $link.TargetPath = $launcher
    $link.Arguments = '--integrations config\concord-live.json'
    $link.WorkingDirectory = $repo
    $link.IconLocation = "$icon,0"
    $link.Description = 'Concord - live model, running locally'
    $link.WindowStyle = 7
    $link.Save()
    Write-Host "Created $repoLink (committed; wired to config\concord-live.json)"
}

Write-Host ''
Write-Host 'Concord is in your Start Menu. Launch it there, or double-click Concord.cmd in the repository.'
Write-Host 'Closing the application window stops Concord. Remove it again with: pwsh scripts/install-shortcut.ps1 -Remove'
