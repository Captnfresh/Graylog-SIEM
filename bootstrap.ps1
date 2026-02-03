# bootstrap.ps1
# Graylog Lab Bootstrap (Inputs + Extractors + SSH Stream)
# Safe to re-run: skips items that already exist.

$ErrorActionPreference = "Stop"

# ----------------------------
# CONFIG - adjust if needed
# ----------------------------
$GRAYLOG_URL = "http://localhost:9000"
$API_BASE    = "$GRAYLOG_URL/api"

$ADMIN_USER  = "admin"
$ADMIN_PASS  = "Admin@12345"

# Repo files (relative to this script)
$INPUTS_FILE     = Join-Path $PSScriptRoot "graylog-config\graylog-inputs.json"
$EXTRACTORS_FILE = Join-Path $PSScriptRoot "graylog-config\graylog-extractors-syslog-tcp.json"

# Stream settings
$SSH_STREAM_TITLE = "SSH Authentication"
$SSH_STREAM_DESC  = "SSH login attempts from syslog"
$SSH_RULE_FIELD   = "message"
$SSH_RULE_TYPE    = "contains"
$SSH_RULE_VALUE   = "sshd"

# ----------------------------
# Helpers
# ----------------------------
function Get-BasicAuthHeader($user, $pass) {
  $pair  = "$user`:$pass"
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
  $b64   = [Convert]::ToBase64String($bytes)
  return @{
    Authorization  = "Basic $b64"
    "X-Requested-By" = "bootstrap"
    Accept         = "application/json"
  }
}

$headers = Get-BasicAuthHeader $ADMIN_USER $ADMIN_PASS

function Invoke-Api($method, $uri, $bodyObj = $null) {
  if ($null -ne $bodyObj) {
    $json = $bodyObj | ConvertTo-Json -Depth 20
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $json -ContentType "application/json"
  } else {
    return Invoke-RestMethod -Method $method -Uri $uri -Headers $headers
  }
}

function Wait-For-Graylog {
  Write-Host "Waiting for Graylog API at $API_BASE ..."
  $tries = 30
  for ($i=1; $i -le $tries; $i++) {
    try {
      Invoke-Api GET "$API_BASE/system" | Out-Null
      Write-Host "Graylog API is reachable."
      return
    } catch {
      Start-Sleep -Seconds 2
    }
  }
  throw "Graylog API not reachable after waiting. Is docker compose up and Graylog healthy?"
}

function Ensure-File($path) {
  if (!(Test-Path $path)) { throw "Missing required file: $path" }
}

# ----------------------------
# Start
# ----------------------------
Write-Host "== Graylog bootstrap starting =="

Wait-For-Graylog
Ensure-File $INPUTS_FILE
Ensure-File $EXTRACTORS_FILE

# ----------------------------
# Get node id (needed for input creation)
# ----------------------------
$nodes = Invoke-Api GET "$API_BASE/system/cluster/nodes"
$nodeId = $nodes.nodes[0].node_id
Write-Host "Using node: $nodeId"

# ----------------------------
# Load desired inputs from export file
# ----------------------------
$inputsJson = Get-Content $INPUTS_FILE -Raw | ConvertFrom-Json
$desiredInputs = $inputsJson.inputs

# Get existing inputs
$existingInputs = (Invoke-Api GET "$API_BASE/system/inputs").inputs

function Get-InputByTitle($title) {
  return $existingInputs | Where-Object { $_.title -eq $title } | Select-Object -First 1
}

# Create missing inputs
foreach ($inp in $desiredInputs) {
  $title = $inp.title
  $found = Get-InputByTitle $title
  if ($found) {
    Write-Host "Input exists: $title (skipping)"
    continue
  }

  Write-Host "Creating input: $title"

  $payload = @{
    title         = $inp.title
    type          = $inp.type
    global        = $false
    node          = $nodeId
    configuration = $inp.attributes
  }

  Invoke-Api POST "$API_BASE/system/inputs" $payload | Out-Null
  Write-Host "Created input: $title"
}

# Refresh inputs list after creation
$existingInputs = (Invoke-Api GET "$API_BASE/system/inputs").inputs

# ----------------------------
# Ensure SSH stream exists + has a rule
# ----------------------------
$streams = (Invoke-Api GET "$API_BASE/streams").streams

function Get-StreamByTitle($title) {
  return $streams | Where-Object { $_.title -eq $title } | Select-Object -First 1
}

$sshStream = Get-StreamByTitle $SSH_STREAM_TITLE
if (!$sshStream) {
  Write-Host "Creating stream: $SSH_STREAM_TITLE"

  $streamPayload = @{
    title       = $SSH_STREAM_TITLE
    description = $SSH_STREAM_DESC
    matching_type = "AND"
    remove_matches_from_default_stream = $false
    index_set_id = $null  # keep default index set
  }

  $created = Invoke-Api POST "$API_BASE/streams" $streamPayload
  # Refresh streams
  $streams = (Invoke-Api GET "$API_BASE/streams").streams
  $sshStream = Get-StreamByTitle $SSH_STREAM_TITLE
  Write-Host "Created stream: $SSH_STREAM_TITLE"
} else {
  Write-Host "Stream exists: $SSH_STREAM_TITLE (skipping create)"
}

# Start stream if stopped
# Graylog has endpoints: POST /streams/{id}/resume (start) and /pause (stop)
try {
  Invoke-Api POST "$API_BASE/streams/$($sshStream.id)/resume" | Out-Null
  Write-Host "Ensured stream is running: $SSH_STREAM_TITLE"
} catch {
  # Some setups may already be running; ignore start errors
  Write-Host "Stream start check: already running or not required."
}

# Ensure stream rule exists (message contains sshd)
$rules = (Invoke-Api GET "$API_BASE/streams/$($sshStream.id)/rules").rules

function StreamRuleExists($field, $type, $value) {
  return $rules | Where-Object {
    $_.field -eq $field -and $_.type -eq $type -and $_.value -eq $value
  } | Select-Object -First 1
}

if (StreamRuleExists $SSH_RULE_FIELD $SSH_RULE_TYPE $SSH_RULE_VALUE) {
  Write-Host "Stream rule exists: $SSH_RULE_FIELD $SSH_RULE_TYPE '$SSH_RULE_VALUE' (skipping)"
} else {
  Write-Host "Creating stream rule: $SSH_RULE_FIELD $SSH_RULE_TYPE '$SSH_RULE_VALUE'"
  $rulePayload = @{
    field = $SSH_RULE_FIELD
    type  = $SSH_RULE_TYPE
    value = $SSH_RULE_VALUE
    inverted = $false
    description = "Route SSH logs"
  }
  Invoke-Api POST "$API_BASE/streams/$($sshStream.id)/rules" $rulePayload | Out-Null
  Write-Host "Created stream rule."
}

# ----------------------------
# Ensure syslog-tcp exists (for extractors)
# ----------------------------
$syslogTcp = $existingInputs | Where-Object { $_.title -eq "syslog-tcp" } | Select-Object -First 1
if (!$syslogTcp) { throw "syslog-tcp input not found. Check your inputs export file and Graylog UI." }

$syslogTcpId = $syslogTcp.id
Write-Host "syslog-tcp input id: $syslogTcpId"

# ----------------------------
# Load desired extractors
# ----------------------------
$extractorsJson = Get-Content $EXTRACTORS_FILE -Raw | ConvertFrom-Json
$desiredExtractors = $extractorsJson.extractors

# Get existing extractors for syslog-tcp
$existingExtractors = (Invoke-Api GET "$API_BASE/system/inputs/$syslogTcpId/extractors").extractors

function ExtractorExists($title) {
  return $existingExtractors | Where-Object { $_.title -eq $title } | Select-Object -First 1
}

# Create missing extractors
foreach ($ex in $desiredExtractors) {
  $title = $ex.title
  if (ExtractorExists $title) {
    Write-Host "Extractor exists: $title (skipping)"
    continue
  }

  Write-Host "Creating extractor: $title"

  # IMPORTANT: Graylog expects extractor_type, not type
  $payload = @{
    title          = $ex.title
    extractor_type = $ex.type
    source_field   = $ex.source_field
    target_field   = $ex.target_field
    extractor_config = $ex.extractor_config
    condition_type = $ex.condition_type
    condition_value = $ex.condition_value
    converters     = $ex.converters
    cursor_strategy = $ex.cursor_strategy
    order          = 0
  }

  Invoke-Api POST "$API_BASE/system/inputs/$syslogTcpId/extractors" $payload | Out-Null
  Write-Host "Created extractor: $title"
}

Write-Host "== Bootstrap complete =="
Write-Host "Next: send test logs and verify fields + stream routing."
