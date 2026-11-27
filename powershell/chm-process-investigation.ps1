param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvtxPath,

    [string]$CsvPath
)

$processEvents = Get-WinEvent -LiteralPath $EvtxPath -FilterXPath "*[System[(EventID=1)]]" |
    ForEach-Object {
        $event = $_
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.GetAttribute("Name")] = $item.InnerText
        }

        [PSCustomObject]@{
            TimeCreated       = $event.TimeCreated
            Image             = $data.Image
            CommandLine       = $data.CommandLine
            ParentImage       = $data.ParentImage
            ParentCommandLine = $data.ParentCommandLine
            ProcessGuid       = $data.ProcessGuid
            ParentProcessGuid = $data.ParentProcessGuid
            Hashes            = $data.Hashes
        }
    }

$processEvents | Sort-Object TimeCreated | Format-List

if ($CsvPath) {
    $parent = Split-Path -Parent $CsvPath
    if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "CSV output directory does not exist: $parent"
    }

    $processEvents | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
    if (Test-Path -LiteralPath $CsvPath -PathType Leaf) {
        Write-Host "CSV export verified: $CsvPath" -ForegroundColor Green
    }
}

# Documented follow-up: check network, file-create and DNS events in the specified interval.
$start = [datetime]"2019-07-26 09:39:10"
$end   = [datetime]"2019-07-26 09:39:20"

Get-WinEvent -LiteralPath $EvtxPath |
    Where-Object {
        $_.Id -in 3, 11, 22 -and
        $_.TimeCreated -ge $start -and
        $_.TimeCreated -le $end
    } |
    Select-Object TimeCreated, Id, Message |
    Format-List
