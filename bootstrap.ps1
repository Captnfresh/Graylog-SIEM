# bootstrap.ps1
# Graylog Lab Bootstrap (Phase 1 & 2)
# Creates Inputs + Extractors from repo JSON exports using Graylog REST API.
# Safe to re-run: skips items that already exist (by title).
#
# Optional env overrides:
#   $env:GRAYLOG_URL="http://localhost:9000"
#   $env:GRAYLOG_USER="admin"
#   $env:GRAYLOG_PASS="Admin@12345"

$ErrorActionPreference = "Stop"

# -----------------------------
# Config / Defaults (override via env vars)
# -----------------------------
$GRAYLOG_URL = if ($env:GRAYLOG_URL) { $env:GRAYLOG_URL } else { "http://localhost:9000" }
$API_BASE    = "$GRAYLOG_URL/api"

$ADMIN_USER  = if ($env:GRAYLOG_USER) { $env:GRAYLOG_USER } else { "admin" }
$ADMIN_PASS  = if ($env:GRAYLOG_PASS) { $env:GRAYLOG_PASS } else { "Admin@12345" }

# Where JSON exports live (relative to this script)
$CONFIG_DIR = Join-Path $PSScriptRoot "graylog-config"
$INPUTS_FILE = Join-Path $CONFIG_DIR "graylog-inputs.json"
$EXTRACTORS_FILE_SYSLOG_TCP = Join-Path $CONFIG_DIR "graylog-extractors-syslog-tcp.json"

# Input title we attach extractors to
$SYSLOG_TCP_TITLE = "syslog-tcp"

# API readiness retry settings
$MAX_RETRIES = 60
$SLEEP_SECONDS = 2

# -----------------------------
# Helpers
# -----------------------------
function New-BasicAuthHeaders([string]$user, [string]$pass) {
  $pair = "$user`:$pass"
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
  $b64 = [Convert]::ToBase64String($bytes)

  return @{
    Authorization    = "Basic $b64"
    "X-Requested-By" = "bootstrap"
    Accept           = "application/json"
  }
}

function Invoke-Graylog([string]$Method, [string]$Uri, $Headers, $BodyObj = $null) {
  if ($null -ne $BodyObj) {
    $json = $BodyObj | ConvertTo-Json -Depth 30
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $json -ContentType "application/json"
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers
  }
}

function Wait-ForGraylogApi($Headers) {
  Write-Host "Waiting for Graylog API at $API_BASE ..."
  for ($i=1; $i -le $MAX_RETRIES; $i++) {
    try {
      $null = Invoke-Graylog -Method GET -Uri "$API_BASE/system/lbstatus" -Headers $Headers
      Write-Host "Graylog API is reachable (attempt $i)." -ForegroundColor Green
      return
    } catch {
      try {
        $null = Invoke-Graylog -Method GET -Uri "$API_BASE/system" -Headers $Headers
        Write-Host "Graylog API is reachable (attempt $i)." -ForegroundColor Green
        return
      } catch {
        Write-Host "Not ready yet (attempt $i/$MAX_RETRIES). Retrying in $SLEEP_SECONDS sec..."
        Start-Sleep -Seconds $SLEEP_SECONDS
      }
    }
  }
  throw "Graylog API not reachable after $MAX_RETRIES attempts. Check containers, URL, and credentials."
}

function Get-FirstNodeId($Headers) {
  $cluster = Invoke-Graylog -Method GET -Uri "$API_BASE/system/cluster/nodes" -Headers $Headers
  if (-not $cluster -or -not $cluster.nodes -or $cluster.nodes.Count -lt 1) {
    throw "No Graylog nodes returned from /system/cluster/nodes. Graylog may not be fully started."
  }

  $leader = $cluster.nodes | Where-Object { $_.is_leader -eq $true } | Select-Object -First 1
  if ($leader) { return $leader.node_id }

  return $cluster.nodes[0].node_id
}

function Read-JsonFile([string]$Path) {
  if (!(Test-Path $Path)) { throw "Missing file: $Path" }
  return (Get-Content $Path -Raw | ConvertFrom-Json)
}

function Get-Inputs($Headers) {
  return (Invoke-Graylog -Method GET -Uri "$API_BASE/system/inputs" -Headers $Headers).inputs
}

function Get-InputByTitle($Headers, [string]$Title) {
  $inputs = Get-Inputs $Headers
  return $inputs | Where-Object { $_.title -eq $Title } | Select-Object -First 1
}

function Ensure-Inputs($Headers, [string]$NodeId, $DesiredInputs) {
  $existing = Get-Inputs $Headers

  foreach ($inp in $DesiredInputs) {
    $title = $inp.title
    $found = $existing | Where-Object { $_.title -eq $title } | Select-Object -First 1

    if ($found) {
      Write-Host "Input exists: $title (skipping)"
      continue
    }

    Write-Host "Creating input: $title" -ForegroundColor Cyan

    $payload = @{
      title         = $inp.title
      type          = $inp.type
      global        = $true
      node          = $NodeId
      configuration = $inp.attributes
    }

    Invoke-Graylog -Method POST -Uri "$API_BASE/system/inputs" -Headers $Headers -BodyObj $payload | Out-Null
    Write-Host "Created input: $title" -ForegroundColor Green

    $existing = Get-Inputs $Headers
  }
}

function Get-ExtractorsForInput($Headers, [string]$InputId) {
  return (Invoke-Graylog -Method GET -Uri "$API_BASE/system/inputs/$InputId/extractors" -Headers $Headers).extractors
}

function Ensure-Extractors($Headers, [string]$InputId, $DesiredExtractors) {
  $existing = Get-ExtractorsForInput $Headers $InputId

  $autoOrder = 0

  foreach ($ex in $DesiredExtractors) {
    $title = $ex.title
    $found = $existing | Where-Object { $_.title -eq $title } | Select-Object -First 1

    if ($found) {
      Write-Host "Extractor exists: $title (skipping)"
      continue
    }

    $orderToUse = $null
    if ($null -ne $ex.order) {
      $orderToUse = [int]$ex.order
    } else {
      $orderToUse = $autoOrder
      $autoOrder++
    }

    if (-not $ex.type) {
      throw "Extractor '$title' is missing 'type' in JSON. Cannot create."
    }

    Write-Host "Creating extractor: $title (order=$orderToUse)" -ForegroundColor Cyan

    # IMPORTANT:
    # Graylog CreateExtractorRequest expects 'extractor_type' (NOT 'type').
    # Sending 'type' causes: "Unable to map property type".
    $payload = @{
      title            = $ex.title
      extractor_type   = $ex.type
      source_field     = $ex.source_field
      target_field     = $ex.target_field
      extractor_config = $ex.extractor_config
      condition_type   = $ex.condition_type
      condition_value  = $ex.condition_value
      converters       = $ex.converters
      cursor_strategy  = $ex.cursor_strategy
      order            = $orderToUse
    }

    Invoke-Graylog -Method POST -Uri "$API_BASE/system/inputs/$InputId/extractors" -Headers $Headers -BodyObj $payload | Out-Null
    Write-Host "Created extractor: $title" -ForegroundColor Green

    $existing = Get-ExtractorsForInput $Headers $InputId
  }
}

# -----------------------------
# Main
# -----------------------------
Write-Host "== Graylog bootstrap starting ==" -ForegroundColor White
Write-Host "Graylog URL: $GRAYLOG_URL"
Write-Host "API Base:    $API_BASE"
Write-Host "User:        $ADMIN_USER"
Write-Host ""

$headers = New-BasicAuthHeaders $ADMIN_USER $ADMIN_PASS

Wait-ForGraylogApi $headers

$nodeId = Get-FirstNodeId $headers
Write-Host "Using node: $nodeId" -ForegroundColor Yellow

$inputsJson = Read-JsonFile $INPUTS_FILE
if (-not $inputsJson.inputs) { throw "No 'inputs' array found in $INPUTS_FILE" }

Ensure-Inputs -Headers $headers -NodeId $nodeId -DesiredInputs $inputsJson.inputs

$syslogTcp = Get-InputByTitle $headers $SYSLOG_TCP_TITLE
if (-not $syslogTcp) { throw "Input '$SYSLOG_TCP_TITLE' not found after creation." }

$syslogTcpId = $syslogTcp.id
Write-Host "syslog-tcp input id: $syslogTcpId" -ForegroundColor Yellow

$extractorsJson = Read-JsonFile $EXTRACTORS_FILE_SYSLOG_TCP
if (-not $extractorsJson.extractors) { throw "No 'extractors' array found in $EXTRACTORS_FILE_SYSLOG_TCP" }

Ensure-Extractors -Headers $headers -InputId $syslogTcpId -DesiredExtractors $extractorsJson.extractors

Write-Host ""
Write-Host "== Bootstrap complete ==" -ForegroundColor Green
Write-Host "Next: send a test SSH log and confirm fields show in Graylog search."