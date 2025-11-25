$files = Get-ChildItem -Path 'd:\projects\contexa' -Recurse -Include *.java | Where-Object {
    $_.FullName -notlike '*\build\*' -and
    $_.FullName -notlike '*\.gradle\*'
}

$count = 0

foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    $original = $content

    # enums 패키지 경로 변경
    $content = $content -replace 'import io\.contexa\.contexaidentity\.security\.enums\.', 'import io.contexa.contexacommon.enums.'

    # properties 패키지 경로 변경
    $content = $content -replace 'import io\.contexa\.contexaidentity\.security\.properties\.', 'import io.contexa.contexacommon.properties.'

    # contexa-core의 AuthContextProperties, MfaSettings 경로 변경
    $content = $content -replace 'import io\.contexa\.contexacore\.properties\.AuthContextProperties', 'import io.contexa.contexacommon.properties.AuthContextProperties'
    $content = $content -replace 'import io\.contexa\.contexacore\.properties\.MfaSettings', 'import io.contexa.contexacommon.properties.MfaSettings'

    if ($content -ne $original) {
        Set-Content -Path $file.FullName -Value $content -NoNewline -Encoding UTF8
        $count++
        Write-Host "Updated: $($file.FullName)"
    }
}

Write-Host "`nTotal files updated: $count"
