param(
    [string]$BaseUrl = "http://localhost:10057",
    [string]$Username = "admin",
    [string]$Password = "1234",
    [string]$Metric = "eir",
    [string[]]$Metrics = @(),
    [string]$EndpointKey = "sensitive",
    [string]$ResourceId = "resource-001",
    [string]$UserId = "",
    [string]$SubjectAccount = "",
    [string[]]$ComparisonAccounts = @(),
    [string]$ExecutionCondition = "",
    [int]$RequestedRunCount = 0,
    [int]$RunTimeoutSec = 420,
    [switch]$ResetZeroTrustState
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ([string]::IsNullOrWhiteSpace($UserId)) {
    $UserId = $Username
}

$outDir = "D:\contexa\build\enterprise-demo"
$loginResponsePath = Join-Path $outDir "login-response.json"
$metricRunPath = Join-Path $outDir ($Metric + "-run-final.json")
$evidencePath = Join-Path $outDir ($Metric + "-evidence-final.json")
$evidenceExportJsonPath = Join-Path $outDir ($Metric + "-evidence-export-final.json")
$evidenceHtmlPath = Join-Path $outDir ($Metric + "-evidence-final.html")
$selectFactorPagePath = Join-Path $outDir "select-factor-page.html"
$ottRequestPagePath = Join-Path $outDir "ott-request-page.html"
$ottVerifyPagePath = Join-Path $outDir "challenge-ott-smoke.html"
$queryJavaPath = Join-Path $outDir "QueryOttCode.java"
$queryClassPath = Join-Path $outDir "QueryOttCode.class"
$allMetricCodes = @("eir", "ccr", "ccsr", "pfr", "mtr", "cor", "rap", "rpi", "bma", "usns", "bsr", "cdc", "era", "suhr")

$deviceId = [Guid]::NewGuid().ToString()
$browserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
$currentMfaSessionId = $null
$currentMfaStepId = $null

function Get-PostgresDriverJar {
    $jar = Get-ChildItem -Path "$env:USERPROFILE\.gradle\caches\modules-2\files-2.1\org.postgresql\postgresql" `
        -Recurse -Filter "postgresql-*.jar" |
        Where-Object { $_.Name -notlike "*sources*" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $jar) {
        throw "PostgreSQL JDBC jar not found in Gradle cache."
    }
    return $jar
}

function Ensure-QueryOttCodeClass {
    param([string]$DriverJar)

    if (Test-Path $queryClassPath) {
        return
    }

@"
import java.sql.*;
public class QueryOttCode {
  public static void main(String[] args) throws Exception {
    Class.forName("org.postgresql.Driver");
    try (Connection c = DriverManager.getConnection(
            "jdbc:postgresql://localhost:5432/contexa",
            "contexa",
            "contexa1234!@#");
         PreparedStatement ps = c.prepareStatement(
            "select token_value from public.one_time_tokens where username = ? order by expires_at desc limit 1")) {
      ps.setString(1, args[0]);
      try (ResultSet rs = ps.executeQuery()) {
        if (rs.next()) {
          System.out.print(rs.getString(1));
        }
      }
    }
  }
}
"@ | Set-Content -Encoding Ascii $queryJavaPath

    javac -cp $DriverJar $queryJavaPath
}

function Get-LatestOttCode {
    param(
        [string]$DriverJar,
        [string]$User
    )

    $token = java -cp "$outDir;$DriverJar" QueryOttCode $User
    if (-not $token) {
        throw "Latest OTT token not found for user '$User'."
    }
    return $token.Trim()
}

function Reset-ZeroTrustState {
    param([string]$ResolvedUserId)

    $keys = @(
        "security:hcad:analysis:$ResolvedUserId",
        "security:hcad:lastAction:$ResolvedUserId",
        "security:hcad:lastActionContext:$ResolvedUserId",
        "security:blocked:users:$ResolvedUserId",
        "security:block:mfa:pending:$ResolvedUserId",
        "security:block:mfa:verified:$ResolvedUserId",
        "security:block:mfa:failCount:$ResolvedUserId",
        "security:escalate:retry:$ResolvedUserId"
    )

    foreach ($key in $keys) {
        docker exec contexa-redis redis-cli DEL $key | Out-Null
    }
}

function Get-AbsoluteUrl {
    param(
        [string]$Origin,
        [string]$PathOrUrl
    )

    if ([string]::IsNullOrWhiteSpace($PathOrUrl)) {
        return $Origin
    }

    if ($PathOrUrl -match '^https?://') {
        return $PathOrUrl
    }

    return ([Uri]::new([Uri]$Origin, $PathOrUrl)).AbsoluteUri
}

function Try-ParseJson {
    param([string]$Content)

    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $null
    }

    try {
        return $Content | ConvertFrom-Json
    }
    catch {
        return $null
    }
}

function Get-AvailableFactorsFromHtml {
    param([string]$Html)

    $matches = [regex]::Matches($Html, 'data-factor-type="([^"]+)"')
    return $matches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
}

function Get-FormAction {
    param(
        [string]$Html,
        [string[]]$FormIds
    )

    if ([string]::IsNullOrWhiteSpace($Html)) {
        return $null
    }

    foreach ($formId in $FormIds) {
        if ([string]::IsNullOrWhiteSpace($formId)) {
            continue
        }

        $idToken = 'id="' + $formId + '"'
        $formIdIndex = $Html.IndexOf($idToken, [System.StringComparison]::Ordinal)
        if ($formIdIndex -lt 0) {
            continue
        }

        $formStart = $Html.LastIndexOf("<form", $formIdIndex, [System.StringComparison]::Ordinal)
        if ($formStart -lt 0) {
            continue
        }

        $actionStart = $Html.IndexOf('action="', $formStart, [System.StringComparison]::Ordinal)
        if ($actionStart -lt 0) {
            continue
        }

        $valueStart = $actionStart + 'action="'.Length
        $valueEnd = $Html.IndexOf('"', $valueStart, [System.StringComparison]::Ordinal)
        if ($valueEnd -gt $valueStart) {
            return $Html.Substring($valueStart, $valueEnd - $valueStart)
        }
    }

    return $null
}

function Get-HiddenInputsFromForm {
    param(
        [string]$Html,
        [string[]]$FormIds
    )

    $hiddenInputs = [ordered]@{}
    if ([string]::IsNullOrWhiteSpace($Html)) {
        return $hiddenInputs
    }

    foreach ($formId in $FormIds) {
        if ([string]::IsNullOrWhiteSpace($formId)) {
            continue
        }

        $idToken = 'id="' + $formId + '"'
        $formIdIndex = $Html.IndexOf($idToken, [System.StringComparison]::Ordinal)
        if ($formIdIndex -lt 0) {
            continue
        }

        $formStart = $Html.LastIndexOf("<form", $formIdIndex, [System.StringComparison]::Ordinal)
        $formEnd = $Html.IndexOf("</form>", $formIdIndex, [System.StringComparison]::Ordinal)
        if ($formStart -lt 0 -or $formEnd -lt 0) {
            continue
        }

        $formHtml = $Html.Substring($formStart, ($formEnd + "</form>".Length) - $formStart)
        foreach ($match in [regex]::Matches($formHtml, '<input\b[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"[^>]*>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hiddenInputs[$match.Groups[1].Value] = $match.Groups[2].Value
        }
        return $hiddenInputs
    }

    return $hiddenInputs
}

function ConvertTo-FormEncodedBody {
    param([hashtable]$Values)

    $pairs = foreach ($entry in $Values.GetEnumerator()) {
        [System.Uri]::EscapeDataString([string]$entry.Key) + "=" + [System.Uri]::EscapeDataString([string]$entry.Value)
    }
    return ($pairs -join "&")
}

function New-BrowserHeaders {
    param([string]$Accept)

    $headers = @{
        "Accept" = $Accept
        "User-Agent" = $browserUserAgent
        "X-Device-Id" = $deviceId
    }
    if ([string]::IsNullOrWhiteSpace($currentMfaSessionId) -eq $false) {
        $headers["X-MFA-Session-Id"] = $currentMfaSessionId
    }
    if ([string]::IsNullOrWhiteSpace($currentMfaStepId) -eq $false) {
        $headers["X-MFA-Step-Id"] = $currentMfaStepId
    }
    return $headers
}

function Invoke-PostForm {
    param(
        [string]$Uri,
        [hashtable]$BodyMap,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [hashtable]$Headers
    )

    $body = ConvertTo-FormEncodedBody -Values $BodyMap
    return Invoke-WebRequest -UseBasicParsing `
        -Method Post `
        -Uri $Uri `
        -ContentType "application/x-www-form-urlencoded" `
        -Body $body `
        -Headers $Headers `
        -WebSession $Session `
        -TimeoutSec 30
}

function Resolve-OttRequestPage {
    param(
        [string]$Origin,
        [object]$LoginJson,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string]$User,
        [string]$SelectFactorPagePath,
        [string]$OttRequestPagePath
    )

    if ($null -eq $LoginJson) {
        throw "Primary login response was not JSON. OTT smoke requires JSON MFA response."
    }

    if ([string]::IsNullOrWhiteSpace($LoginJson.nextStepUrl)) {
        throw "Primary login response does not include nextStepUrl."
    }

    $nextStepUrl = Get-AbsoluteUrl -Origin $Origin -PathOrUrl $LoginJson.nextStepUrl

    if (($LoginJson.nextFactorType -eq 'MFA_OTT') -or ($nextStepUrl -match '/mfa/ott/request-code-ui$')) {
        $page = Invoke-WebRequest -UseBasicParsing -Uri $nextStepUrl -Headers (New-BrowserHeaders -Accept "text/html") -WebSession $Session -TimeoutSec 30
        $page.Content | Set-Content -Encoding UTF8 $OttRequestPagePath
        return $page.Content
    }

    if ($nextStepUrl -match '/mfa/select-factor$') {
        $selectPage = Invoke-WebRequest -UseBasicParsing -Uri $nextStepUrl -Headers (New-BrowserHeaders -Accept "text/html") -WebSession $Session -TimeoutSec 30
        $selectPage.Content | Set-Content -Encoding UTF8 $SelectFactorPagePath

        $availableFactors = @(Get-AvailableFactorsFromHtml -Html $selectPage.Content)
        if ($availableFactors -notcontains 'MFA_OTT') {
            $availableSummary = if ($availableFactors.Count -gt 0) { $availableFactors -join ', ' } else { 'none' }
            throw "OTT factor is not available in select-factor page. Available factors: $availableSummary"
        }

        $selectBody = @{ factorType = 'MFA_OTT'; username = $User } | ConvertTo-Json -Compress
        $selectResponse = Invoke-WebRequest -UseBasicParsing `
            -Method Post `
            -Uri $nextStepUrl `
            -ContentType 'application/json' `
            -Body $selectBody `
            -Headers (New-BrowserHeaders -Accept "application/json") `
            -WebSession $Session `
            -TimeoutSec 30

        $selectJson = Try-ParseJson -Content $selectResponse.Content
        if ($null -eq $selectJson -or [string]::IsNullOrWhiteSpace($selectJson.nextStepUrl)) {
            throw "Select-factor response did not return a JSON nextStepUrl for OTT."
        }

        $ottRequestUrl = Get-AbsoluteUrl -Origin $Origin -PathOrUrl $selectJson.nextStepUrl
        $ottPage = Invoke-WebRequest -UseBasicParsing -Uri $ottRequestUrl -Headers (New-BrowserHeaders -Accept "text/html") -WebSession $Session -TimeoutSec 30
        $ottPage.Content | Set-Content -Encoding UTF8 $OttRequestPagePath
        return $ottPage.Content
    }

    throw "Login flow requested non-OTT next step: factor=$($LoginJson.nextFactorType), nextStepUrl=$($LoginJson.nextStepUrl)"
}

function Wait-ForMetricRunCompletion {
    param(
        [string]$BaseUrl,
        [string]$MetricCode,
        [string]$RunId,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$TimeoutSec
    )

    if ([string]::IsNullOrWhiteSpace($RunId)) {
        throw "Metric run response does not include runId."
    }

    $deadline = (Get-Date).AddSeconds([Math]::Max($TimeoutSec, 30))
    $detailUrl = "$BaseUrl/admin/api/enterprise/verification/context/$MetricCode/runs/$RunId"
    $lastRunResponse = $null

    do {
        $detailResponse = Invoke-WebRequest -UseBasicParsing `
            -Uri $detailUrl `
            -Headers (New-BrowserHeaders -Accept "application/json") `
            -WebSession $Session `
            -TimeoutSec 45

        $detailJson = Try-ParseJson -Content $detailResponse.Content
        if ($null -ne $detailJson -and $null -ne $detailJson.run) {
            $lastRunResponse = $detailJson
            $state = [string]$detailJson.run.state
            $completedAt = [string]$detailJson.run.completedAt
            if ((-not [string]::IsNullOrWhiteSpace($completedAt)) -or ($state -and $state.Trim().ToUpperInvariant() -ne 'RUNNING')) {
                return $detailJson
            }
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    if ($null -ne $lastRunResponse) {
        return $lastRunResponse
    }

    throw "Timed out waiting for metric '$MetricCode' run '$RunId' to complete."
}


if ($ResetZeroTrustState) {
    Reset-ZeroTrustState -ResolvedUserId $UserId
}

$driverJar = Get-PostgresDriverJar
Ensure-QueryOttCodeClass -DriverJar $driverJar

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/admin/mfa/login" -Headers (New-BrowserHeaders -Accept "text/html") -WebSession $session -TimeoutSec 30 | Out-Null

$loginResponse = Invoke-WebRequest -UseBasicParsing `
    -Method Post `
    -Uri "$BaseUrl/admin/mfa/login" `
    -ContentType "application/x-www-form-urlencoded" `
    -Headers (New-BrowserHeaders -Accept "application/json") `
    -Body ("username=" + [System.Uri]::EscapeDataString($Username) + "&password=" + [System.Uri]::EscapeDataString($Password)) `
    -WebSession $session `
    -TimeoutSec 30

$loginResponse.Content | Set-Content -Encoding UTF8 $loginResponsePath
$loginJson = Try-ParseJson -Content $loginResponse.Content
$currentMfaSessionId = $loginJson.mfaSessionId
$currentMfaStepId = $loginJson.nextStepId
$ottPageHtml = Resolve-OttRequestPage `
    -Origin $BaseUrl `
    -LoginJson $loginJson `
    -Session $session `
    -User $Username `
    -SelectFactorPagePath $selectFactorPagePath `
    -OttRequestPagePath $ottRequestPagePath

$ottRequestAction = Get-FormAction -Html $ottPageHtml -FormIds @("ottRequestForm", "ott-request-form")
if ([string]::IsNullOrWhiteSpace($ottRequestAction)) {
    throw "Could not resolve OTT code generation action from request page."
}

$requestCodeForm = Get-HiddenInputsFromForm -Html $ottPageHtml -FormIds @("ottRequestForm", "ott-request-form")
if (-not $requestCodeForm.Contains("username")) {
    $requestCodeForm["username"] = $Username
}

$codeGenerationUrl = Get-AbsoluteUrl -Origin $BaseUrl -PathOrUrl $ottRequestAction
$requestCodeResponse = Invoke-PostForm `
    -Uri $codeGenerationUrl `
    -BodyMap $requestCodeForm `
    -Session $session `
    -Headers (New-BrowserHeaders -Accept "application/json")

$verifyPageHtml = $requestCodeResponse.Content
$verifyPageHtml | Set-Content -Encoding UTF8 $ottVerifyPagePath
$verifyPageUrl = if ($requestCodeResponse.BaseResponse -and $requestCodeResponse.BaseResponse.ResponseUri) {
    $requestCodeResponse.BaseResponse.ResponseUri.AbsoluteUri
} else {
    $null
}
if ([string]::IsNullOrWhiteSpace($verifyPageUrl)) {
    $verifyPageUrl = $requestCodeResponse.Headers["Location"]
}
if ([string]::IsNullOrWhiteSpace($verifyPageUrl)) {
    throw "OTT code generation did not resolve a verification page URL."
}

$verifyAction = Get-FormAction -Html $verifyPageHtml -FormIds @("verifyForm", "ott-verify-form")
if ([string]::IsNullOrWhiteSpace($verifyAction)) {
    throw "Could not resolve OTT verification action from verification page."
}

Start-Sleep -Seconds 1
$token = Get-LatestOttCode -DriverJar $driverJar -User $Username

$verifyForm = Get-HiddenInputsFromForm -Html $verifyPageHtml -FormIds @("verifyForm", "ott-verify-form")
$verifyForm["token"] = $token
$verifyUrl = Get-AbsoluteUrl -Origin $BaseUrl -PathOrUrl $verifyAction

$verifyResponse = Invoke-WebRequest -UseBasicParsing `
    -Method Post `
    -Uri $verifyUrl `
    -ContentType "application/x-www-form-urlencoded" `
    -Headers (New-BrowserHeaders -Accept "application/json") `
    -Body (ConvertTo-FormEncodedBody -Values $verifyForm) `
    -WebSession $session `
    -TimeoutSec 30

$verifyJson = Try-ParseJson -Content $verifyResponse.Content
if ($null -eq $verifyJson) {
    throw "OTT verification did not return JSON. Body=$($verifyResponse.Content)"
}
if ($verifyJson.status -ne "MFA_COMPLETED") {
    throw "OTT verification failed. status=$($verifyJson.status) body=$($verifyResponse.Content)"
}

$metricList = if ($Metrics.Count -gt 0) {
    $Metrics
} elseif ($Metric -eq "*" -or $Metric -eq "all") {
    $allMetricCodes
} else {
    @($Metric)
}

$summary = New-Object System.Collections.Generic.List[object]

function Get-MetricExecutionContract {
    param(
        [string]$MetricCode,
        [string]$FallbackUser,
        [string]$RequestedSubjectAccount,
        [string[]]$RequestedComparisonAccounts,
        [string]$RequestedExecutionCondition,
        [int]$RequestedRunCount
    )

    $normalizedMetric = if ($null -eq $MetricCode) { "" } else { [string]$MetricCode }; $normalizedMetric = $normalizedMetric.Trim().ToLowerInvariant()
    $subjectAccount = if ([string]::IsNullOrWhiteSpace($RequestedSubjectAccount)) { $FallbackUser } else { $RequestedSubjectAccount.Trim() }
    $comparisonAccounts = @($RequestedComparisonAccounts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })

    $defaultExecutionCondition = "single_cycle"
    $defaultRunCount = 1
    switch ($normalizedMetric) {
        "rpi" { $defaultExecutionCondition = "single_repeated"; $defaultRunCount = 3 }
        "bma" { $defaultExecutionCondition = "single_repeated"; $defaultRunCount = 3 }
        "usns" { $defaultExecutionCondition = "single_repeated"; $defaultRunCount = 3 }
        "bsr" { $defaultExecutionCondition = "single_repeated"; $defaultRunCount = 3 }
        "cor" { $defaultExecutionCondition = "multi_cycle"; $defaultRunCount = 1 }
        "rap" { $defaultExecutionCondition = "multi_cycle"; $defaultRunCount = 1 }
    }

    $executionCondition = if ([string]::IsNullOrWhiteSpace($RequestedExecutionCondition)) {
        $defaultExecutionCondition
    } else {
        $RequestedExecutionCondition.Trim().ToLowerInvariant()
    }

    $runCount = if ($RequestedRunCount -gt 0) { $RequestedRunCount } else { $defaultRunCount }
    if ($executionCondition -like "*repeated" -and $runCount -lt 2) {
        $runCount = 2
    }
    if ($executionCondition -notlike "*repeated" -and $runCount -gt 1) {
        $runCount = 1
    }

    [pscustomobject]@{
        ExecutionCondition = $executionCondition
        SubjectAccount = $subjectAccount
        ComparisonAccounts = $comparisonAccounts
        RunCount = $runCount
    }
}

foreach ($metricCode in $metricList) {
    $normalizedMetric = $metricCode.ToLowerInvariant()
    $metricRunPath = Join-Path $outDir ($normalizedMetric + "-run-final.json")
    $evidencePath = Join-Path $outDir ($normalizedMetric + "-evidence-final.json")
    $evidenceExportJsonPath = Join-Path $outDir ($normalizedMetric + "-evidence-export-final.json")
    $evidenceHtmlPath = Join-Path $outDir ($normalizedMetric + "-evidence-final.html")

    $executionContract = Get-MetricExecutionContract `
        -MetricCode $normalizedMetric `
        -FallbackUser $Username `
        -RequestedSubjectAccount $SubjectAccount `
        -RequestedComparisonAccounts $ComparisonAccounts `
        -RequestedExecutionCondition $ExecutionCondition `
        -RequestedRunCount $RequestedRunCount

    $runBodyMap = [ordered]@{
        endpointKey = $EndpointKey
        resourceId = $ResourceId
        executionCondition = $executionContract.ExecutionCondition
        subjectAccount = $executionContract.SubjectAccount
        runCount = $executionContract.RunCount
        rerun = $false
        contaminationSeed = $false
        baselineSeedRequested = $false
    }
    if ($executionContract.ComparisonAccounts.Count -gt 0) {
        $runBodyMap.comparisonAccounts = @($executionContract.ComparisonAccounts)
    }
    $runBody = $runBodyMap | ConvertTo-Json -Compress

    $runRequestTimeoutSec = [Math]::Max(120, $RunTimeoutSec + 30)

    $runResponse = Invoke-WebRequest -UseBasicParsing `
        -Uri "$BaseUrl/admin/api/enterprise/verification/context/$normalizedMetric/runs" `
        -Method Post `
        -ContentType "application/json" `
        -Headers (New-BrowserHeaders -Accept "application/json") `
        -Body $runBody `
        -WebSession $session `
        -TimeoutSec $runRequestTimeoutSec

    $runResponseJson = Try-ParseJson -Content $runResponse.Content
    if ($null -eq $runResponseJson -or $null -eq $runResponseJson.run) {
        throw "Metric run request for '$normalizedMetric' did not return a run payload."
    }

    $runId = [string]$runResponseJson.run.runId
    $runJson = Wait-ForMetricRunCompletion `
        -BaseUrl $BaseUrl `
        -MetricCode $normalizedMetric `
        -RunId $runId `
        -Session $session `
        -TimeoutSec $RunTimeoutSec

    $runJson | ConvertTo-Json -Depth 100 | Set-Content -Encoding UTF8 $metricRunPath
    $requestId = [string]$runJson.run.requestId

    if (-not [string]::IsNullOrWhiteSpace($requestId)) {
        Invoke-WebRequest -UseBasicParsing `
            -Uri "$BaseUrl/admin/api/enterprise/verification/evidence/$requestId" `
            -Headers (New-BrowserHeaders -Accept "application/json") `
            -WebSession $session `
            -TimeoutSec 45 |
            Select-Object -ExpandProperty Content |
            Set-Content -Encoding UTF8 $evidencePath

        Invoke-WebRequest -UseBasicParsing `
            -Uri "$BaseUrl/admin/api/enterprise/verification/evidence/$requestId/export/json" `
            -Headers (New-BrowserHeaders -Accept "application/json") `
            -WebSession $session `
            -TimeoutSec 45 |
            Select-Object -ExpandProperty Content |
            Set-Content -Encoding UTF8 $evidenceExportJsonPath

        Invoke-WebRequest -UseBasicParsing `
            -Uri "$BaseUrl/admin/api/enterprise/verification/evidence/$requestId/export/html" `
            -Headers (New-BrowserHeaders -Accept "text/html") `
            -WebSession $session `
            -TimeoutSec 45 |
            Select-Object -ExpandProperty Content |
            Set-Content -Encoding UTF8 $evidenceHtmlPath
    }

    $summary.Add([pscustomobject]@{
        metric = $normalizedMetric
        runId = $runId
        requestId = $requestId
        score = $runJson.run.score
        state = $runJson.run.state
        runFile = $metricRunPath
        evidenceFile = if ([string]::IsNullOrWhiteSpace($requestId)) { $null } else { $evidencePath }
    }) | Out-Null

    "metric=$normalizedMetric"
    "runId=$runId"
    "requestId=$requestId"
    "score=$($runJson.run.score)"
    "state=$($runJson.run.state)"
    "runFile=$metricRunPath"
    if (-not [string]::IsNullOrWhiteSpace($requestId)) {
        "evidenceFile=$evidencePath"
    }
}

$summaryPath = Join-Path $outDir "metric-summary-final.json"
$summary | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $summaryPath

"token=$token"
"deviceId=$deviceId"
"nextFactorType=$($loginJson.nextFactorType)"
"summaryFile=$summaryPath"


