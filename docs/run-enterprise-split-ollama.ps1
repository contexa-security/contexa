param(
    [int]$ServerPort = 10057,
    [int]$EmbeddingPort = 11435,
    [string]$JarPath = 'D:\contexa-enterprise\spring-boot-starter-contexa-enterprise\build\libs\spring-boot-starter-contexa-enterprise-0.1.0.jar',
    [string]$ChatOllamaBaseUrl = 'http://127.0.0.1:11434',
    [string]$ChatModel = 'qwen3:8b',
    [string]$EmbeddingModel = 'mxbai-embed-large',
    [string]$ChatKeepAlive = '30m',
    [switch]$SkipEmbeddingRuntimeStart
)

$ErrorActionPreference = 'Stop'

function Test-PortListening {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

function Assert-PortFree {
    param([int]$Port, [string]$Label)
    if (Test-PortListening -Port $Port) {
        throw "$Label port $Port is already in use. Stop the existing process first."
    }
}

function Wait-PortListening {
    param([int]$Port, [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortListening -Port $Port) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function New-EncodedCommand {
    param([string]$Command)
    return [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
}

if (-not (Test-Path $JarPath)) {
    throw "Starter jar not found: $JarPath"
}

Assert-PortFree -Port $ServerPort -Label 'Starter server'
if (-not $SkipEmbeddingRuntimeStart) {
    if (-not (Test-PortListening -Port $EmbeddingPort)) {
        $embeddingStdout = "D:\contexa\build\enterprise-demo\ollama-embedding-$EmbeddingPort.log"
        $embeddingStderr = "D:\contexa\build\enterprise-demo\ollama-embedding-$EmbeddingPort.err.log"
        $embeddingCommand = '$env:OLLAMA_HOST="127.0.0.1:{0}"; $env:OLLAMA_KEEP_ALIVE="10m"; $env:OLLAMA_NUM_PARALLEL="1"; $env:OLLAMA_MAX_QUEUE="128"; $env:OLLAMA_MAX_LOADED_MODELS="1"; & "C:\Users\leaven\AppData\Local\Programs\Ollama\ollama.exe" serve' -f $EmbeddingPort
        $embeddingEncodedCommand = New-EncodedCommand -Command $embeddingCommand
        $embeddingProcess = Start-Process -FilePath 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile','-EncodedCommand',$embeddingEncodedCommand -PassThru -WindowStyle Hidden -RedirectStandardOutput $embeddingStdout -RedirectStandardError $embeddingStderr
        if (-not (Wait-PortListening -Port $EmbeddingPort -TimeoutSeconds 30)) {
            throw "Embedding Ollama did not start on port $EmbeddingPort. Check $embeddingStdout and $embeddingStderr"
        }
    }
}

$serverStdout = "D:\contexa\build\enterprise-demo\starter-$ServerPort.log"
$serverStderr = "D:\contexa\build\enterprise-demo\starter-$ServerPort.err.log"
$embeddingBaseUrl = "http://127.0.0.1:$EmbeddingPort"
$starterCommand = '$env:CONTEXA_CHAT_OLLAMA_BASE_URL="{0}"; $env:CONTEXA_CHAT_OLLAMA_MODEL="{1}"; $env:CONTEXA_OLLAMA_CHAT_KEEP_ALIVE="{2}"; $env:CONTEXA_EMBEDDING_OLLAMA_DEDICATED_RUNTIME_ENABLED="true"; $env:CONTEXA_EMBEDDING_OLLAMA_BASE_URL="{3}"; $env:CONTEXA_EMBEDDING_OLLAMA_MODEL="{4}"; & "C:\Program Files\Common Files\Oracle\Java\javapath\java.exe" -jar "{5}" --server.port={6}' -f $ChatOllamaBaseUrl, $ChatModel, $ChatKeepAlive, $embeddingBaseUrl, $EmbeddingModel, $JarPath, $ServerPort
$starterEncodedCommand = New-EncodedCommand -Command $starterCommand
$starterProcess = Start-Process -FilePath 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile','-EncodedCommand',$starterEncodedCommand -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverStdout -RedirectStandardError $serverStderr
if (-not (Wait-PortListening -Port $ServerPort -TimeoutSeconds 60)) {
    throw "Starter server did not start on port $ServerPort. Check $serverStdout and $serverStderr"
}

[pscustomobject]@{
    ServerPort = $ServerPort
    StarterPid = $starterProcess.Id
    StarterBaseUrl = "http://localhost:$ServerPort"
    EmbeddingPort = $EmbeddingPort
    EmbeddingBaseUrl = $embeddingBaseUrl
    SplitRuntimeEnabled = $true
    LogFile = $serverStdout
    ErrorLogFile = $serverStderr
}
