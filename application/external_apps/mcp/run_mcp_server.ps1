# run_mcp_server.ps1
# Start MCP server with streamable HTTP transport

$ErrorActionPreference = "Continue"

$mcpRoot = $PSScriptRoot
$appRoot = Resolve-Path (Join-Path $mcpRoot "..\..\single_app")
$venvPython = Join-Path $appRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Error "Python venv not found: $venvPython"
    exit 1
}

$logDir = Join-Path $mcpRoot "logs"
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}
$stdoutLog = Join-Path $logDir "mcp_stdout.log"

Set-Location -Path $mcpRoot
$env:FASTMCP_HOST = "localhost"
$env:FASTMCP_PORT = "8000"
& $venvPython -c "import server; server.mcp.run(transport='streamable-http')" 2>&1 | Tee-Object -FilePath $stdoutLog
