param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$EvidencePath
)

if (-not (Test-Path -LiteralPath $EvidencePath -PathType Container)) {
    throw "Evidence directory not found: $EvidencePath"
}

$files = Get-ChildItem -LiteralPath $EvidencePath -Filter "*.evtx" -File -Recurse

if (-not $files) {
    Write-Warning "No EVTX files found under: $EvidencePath"
    return
}

foreach ($file in $files) {
    Write-Host "`n=== $($file.Name) ===" -ForegroundColor Cyan

    try {
        Get-WinEvent -LiteralPath $file.FullName -ErrorAction Stop |
            Group-Object -Property Id |
            Sort-Object { [int]$_.Name } |
            Select-Object @{Name = "EventID"; Expression = { [int]$_.Name }}, Count
    }
    catch {
        Write-Warning "Could not read '$($file.Name)': $($_.Exception.Message)"
    }
}
