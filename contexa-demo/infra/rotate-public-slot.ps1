param(
    [Parameter(Mandatory)][string]$SettingsFile,
    [Parameter(Mandatory)][ValidatePattern('^contexa-(runtime-)?lab-[a-z0-9-]{1,40}$')][string]$Project
)
$ErrorActionPreference = 'Stop'
$modulePath = Split-Path -Parent $PSScriptRoot
$composePath = Join-Path $modulePath 'compose.public.yml'
$settingsPath = (Resolve-Path -LiteralPath $SettingsFile).Path
$configuration = @{}
foreach ($line in [IO.File]::ReadAllLines($settingsPath)) {
    if ($line -match '^([A-Z][A-Z0-9_]*)=(.*)$') { $configuration[$Matches[1]] = $Matches[2] }
}
$previousGeneration = [guid]::Parse($configuration['LAB_WORKSPACE_GENERATION']).ToString()
$previousHex = $previousGeneration.Replace('-','')
if ($configuration['LAB_GENERATION_HEX'] -ne $previousHex) { throw 'Generation configuration mismatch' }
$postgres = "${Project}-postgres-1"
$actualProject = & docker inspect $postgres --format '{{index .Config.Labels "com.docker.compose.project"}}'
if ($LASTEXITCODE -ne 0 -or $actualProject.Trim() -ne $Project) { throw 'Control database ownership mismatch' }
$state = & docker exec $postgres psql -U lab -d lab_portal -At -v ON_ERROR_STOP=1 -c "select state from lab.workspace_slot where id='public-one' and generation='$previousGeneration'"
if ($LASTEXITCODE -ne 0 -or $state.Trim() -ne 'RESET_REQUIRED') { throw 'Only a retired slot may be reallocated' }
$active = & docker exec $postgres psql -U lab -d lab_portal -At -v ON_ERROR_STOP=1 -c "select count(*) from lab.workspace_lease where state='ACTIVE' and slot_id='public-one'"
if ($LASTEXITCODE -ne 0 -or $active.Trim() -ne '0') { throw 'An active lease prevents reallocation' }
$generationCount = & docker exec $postgres psql -U lab -d lab_portal -At -c "select count(distinct generation) from lab.workspace_slot_worker"
if ($LASTEXITCODE -ne 0 -or [int]$generationCount -ge 64) { throw 'Retention capacity reached; review owned archives before another generation' }
$nextGeneration = [guid]::NewGuid().ToString()
$nextHex = $nextGeneration.Replace('-','')
$archivePath = "${settingsPath}.${previousHex}.retired"
if (Test-Path -LiteralPath $archivePath) { throw 'Preserve previous retirement record' }
Copy-Item -LiteralPath $settingsPath -Destination $archivePath
& docker compose -p $Project --env-file $settingsPath -f $composePath stop baseline contexa
if ($LASTEXITCODE -ne 0) { throw 'Old workers could not stop; generation was not changed' }
& docker compose -p $Project --env-file $settingsPath -f $composePath stop redis kafka zookeeper
if ($LASTEXITCODE -ne 0) { throw 'Old storage processes could not stop; generation was not changed' }
$configuration['LAB_WORKSPACE_GENERATION'] = $nextGeneration
$configuration['LAB_GENERATION_HEX'] = $nextHex
$lines = $configuration.Keys | Sort-Object | ForEach-Object { "$_=$($configuration[$_])" }
[IO.File]::WriteAllLines($settingsPath, [string[]]$lines)
& docker compose -p $Project --env-file $settingsPath -f $composePath up -d --no-build
if ($LASTEXITCODE -ne 0) { throw 'New generation did not start; preserve both generations and retry the same settings' }
[pscustomobject]@{ Project=$Project; PreviousGeneration=$previousGeneration; NewGeneration=$nextGeneration;
    RawDatabases='Preserved'; OldVolumes='Preserved'; MainEnvironment='Unchanged'; At=(Get-Date).ToString('o') }
