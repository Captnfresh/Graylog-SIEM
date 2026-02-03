# bootstrap.ps1
# Creates Graylog inputs + extractors for the lab using admin credentials.
# Safe to re-run: it skips items that already exist.

$ErrorActionPreference = "Stop"

$GRAYLOG_URL = "http://localhost:9000"
$API_BASE    = "$GRAYLOG_URL/api"

$ADMIN_USER = "admin"
$ADMIN_PASS = "Admin@12345"

function Get-BasicAuthHeader($user, $pass) {
  $pair = "$user`:$pass"
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
  $b64 = [Convert]::ToBase64String($bytes)
  return @{ Authorization = "Basic $b64"; "X-Requested-By" = "bootstrap"; Accept="application/json" }
}

$headers = Get-BasicAuthHeader $ADMIN_USER $ADMIN_PASS

Write-Host "== Graylog bootstrap starting =="

# Get node ID (needed when creating inputs)
$node = Invoke-RestMethod -Method GET -Uri "$API_BASE/system/cluster/nodes" -Headers $headers
$nodeId = $node.nodes[0].node_id
Write-Host "Using node: $nodeId"

# Load desired inputs from exported JSON file
$inputsFile = Join-Path $PSScriptRoot "graylog-config\graylog-inputs.json"
if (!(Test-Path $inputsFile)) { throw "Missing $inputsFile" }

$inputsJson = Get-Content $inputsFile -Raw | ConvertFrom-Json
$desiredInputs = $inputsJson.inputs

# Get existing inputs in Graylog
$existingInputs = (Invoke-RestMethod -Method GET -Uri "$API_BASE/system/inputs" -Headers $headers).inputs

function InputExists($title) {
  return $existingInputs | Where-Object { $_.title -eq $title }
}

# Create missing inputs
foreach ($inp in $desiredInputs) {
  $title = $inp.title

  if (InputExists $title) {
    Write-Host "Input exists: $title (skipping)"
    continue
  }

  Write-Host "Creating input: $title"

  $payload = @{
    title = $inp.title
    type  = $inp.type
    global = $false
    node = $nodeId
    configuration = $inp.attributes
  } | ConvertTo-Json -Depth 10

  Invoke-RestMethod -Method POST -Uri "$API_BASE/system/inputs" -Headers $headers -Body $payload -ContentType "application/json" | Out-Null
  Write-Host "Created input: $title"
}

# Refresh inputs list
$existingInputs = (Invoke-RestMethod -Method GET -Uri "$API_BASE/system/inputs" -Headers $headers).inputs

# Find syslog-tcp input ID
$syslogTcp = $existingInputs | Where-Object { $_.title -eq "syslog-tcp" }
if (!$syslogTcp) { throw "syslog-tcp input not found after creation." }

$syslogTcpId = $syslogTcp.id
Write-Host "syslog-tcp input id: $syslogTcpId"

# Load extractors JSON
$extractorsFile = Join-Path $PSScriptRoot "graylog-config\graylog-extractors-syslog-tcp.json"
if (!(Test-Path $extractorsFile)) { throw "Missing $extractorsFile" }

$extractorsJson = Get-Content $extractorsFile -Raw | ConvertFrom-Json
$desiredExtractors = $extractorsJson.extractors

# Get existing extractors for syslog-tcp
$existingExtractors = (Invoke-RestMethod -Method GET -Uri "$API_BASE/system/inputs/$syslogTcpId/extractors" -Headers $headers).extractors

function ExtractorExists($title) {
  return $existingExtractors | Where-Object { $_.title -eq $title }
}

# Create missing extractors
foreach ($ex in $desiredExtractors) {
  $title = $ex.title

  if (ExtractorExists $title) {
    Write-Host "Extractor exists: $title (skipping)"
    continue
  }

  Write-Host "Creating extractor: $title"

  $payloadObj = @{
    title = $ex.title
    type = $ex.type
    source_field = $ex.source_field
    target_field = $ex.target_field
    extractor_config = $ex.extractor_config
    condition_type = $ex.condition_type
    condition_value = $ex.condition_value
    converters = $ex.converters
    cursor_strategy = $ex.cursor_strategy
    order = 0
  }

  $payload = $payloadObj | ConvertTo-Json -Depth 10

  Invoke-RestMethod -Method POST -Uri "$API_BASE/system/inputs/$syslogTcpId/extractors" -Headers $headers -Body $payload -ContentType "application/json" | Out-Null
  Write-Host "Created extractor: $title"
}

Write-Host "== Bootstrap complete =="
Write-Host "Next: send a test SSH log and confirm fields show in Graylog search."
