$ErrorActionPreference = 'Stop'
$taskWorkspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$taskOutput = Join-Path $taskWorkspace 'upstream'
$taskArchives = Join-Path $taskOutput 'archives'
New-Item -ItemType Directory -Path $taskOutput, $taskArchives -Force | Out-Null
$taskSources = (Get-Content -LiteralPath (Join-Path $taskWorkspace 'sources.lock.json') -Raw | ConvertFrom-Json).sources | Where-Object { $_.kind -eq 'repository' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$taskManifest = @()
foreach ($taskSource in $taskSources) {
  $taskSlug = $taskSource.repository.Replace('/', '--')
  $taskArchive = Join-Path $taskArchives ($taskSlug + '.zip')
  $taskTarget = [IO.Path]::GetFullPath((Join-Path $taskOutput $taskSlug))
  if (-not $taskTarget.StartsWith(([IO.Path]::GetFullPath($taskOutput) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid extraction target' }
  $taskUrl = 'https://codeload.github.com/' + $taskSource.repository + '/zip/' + $taskSource.revision
  if (-not (Test-Path -LiteralPath $taskArchive)) {
    Write-Output ('Acquiring ' + $taskSource.repository + ' at ' + $taskSource.revision)
    Invoke-WebRequest -Uri $taskUrl -OutFile $taskArchive -TimeoutSec 180 -MaximumRedirection 0
  }
  $taskZip = [IO.Compression.ZipFile]::OpenRead($taskArchive)
  try {
    $taskBytes = [long]0
    $taskCount = 0
    $taskLinks = @()
    $taskPrefix = ($taskSource.repository.Split('/')[1] + '-' + $taskSource.revision + '/')
    foreach ($taskEntry in $taskZip.Entries) {
      if (-not $taskEntry.FullName.StartsWith($taskPrefix, [StringComparison]::Ordinal)) { throw 'Unexpected archive root' }
      $taskRelative = $taskEntry.FullName.Substring($taskPrefix.Length)
      if (-not $taskRelative) { continue }
      if ($taskRelative.Contains('\') -or $taskRelative.Contains(':') -or $taskRelative.Split('/').Contains('..')) { throw 'Unsafe archive path' }
      $taskResolved = [IO.Path]::GetFullPath((Join-Path $taskTarget $taskRelative))
      if (-not $taskResolved.StartsWith(($taskTarget + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'Archive entry escapes target' }
      $taskMode = (($taskEntry.ExternalAttributes -shr 16) -band 61440)
      if ($taskMode -eq 40960) { $taskLinks += $taskRelative }
      $taskBytes += $taskEntry.Length
      if ($taskBytes -gt 1073741824 -or $taskZip.Entries.Count -gt 100000) { throw 'Archive exceeds acquisition budget' }
      if ($taskEntry.FullName.EndsWith('/')) { continue }
      $taskCount++
    }
    if (-not (Test-Path -LiteralPath $taskTarget)) {
      New-Item -ItemType Directory -Path $taskTarget | Out-Null
      foreach ($taskEntry in $taskZip.Entries) {
        $taskRelative = $taskEntry.FullName.Substring($taskPrefix.Length)
        if (-not $taskRelative) { continue }
        $taskResolved = [IO.Path]::GetFullPath((Join-Path $taskTarget $taskRelative))
        if ($taskEntry.FullName.EndsWith('/')) { New-Item -ItemType Directory -Path $taskResolved -Force | Out-Null; continue }
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($taskResolved)) -Force | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($taskEntry, $taskResolved, $false)
      }
    }
    New-Item -ItemType Directory -Path (Join-Path $taskOutput 'archives') -Force | Out-Null
    if ([IO.Path]::GetFullPath($taskArchive) -ne [IO.Path]::GetFullPath((Join-Path $taskOutput ('archives/' + $taskSlug + '.zip')))) { Copy-Item -LiteralPath $taskArchive -Destination (Join-Path $taskOutput ('archives/' + $taskSlug + '.zip')) -Force }
    $taskManifest += [ordered]@{repository=$taskSource.repository; revision=$taskSource.revision; license=$taskSource.license; archiveUrl=$taskUrl; archiveSha256=(Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash.ToLowerInvariant(); files=$taskCount; bytes=$taskBytes; directory=('upstream/' + $taskSlug); symlinksMaterializedAsText=$taskLinks}
    $taskManifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $taskOutput 'manifest.json') -Encoding utf8NoBOM
    Write-Output ('Captured ' + $taskCount + ' files, ' + $taskBytes + ' bytes from ' + $taskSource.repository)
  } finally { $taskZip.Dispose() }
}

