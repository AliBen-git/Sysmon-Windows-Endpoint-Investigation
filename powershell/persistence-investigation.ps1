param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvtxPath
)

Get-WinEvent -LiteralPath $EvtxPath -FilterXPath "*[System[(EventID=13)]]" |
    ForEach-Object {
        $event = $_
        [xml]$xml = $event.ToXml()
        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.GetAttribute("Name")] = $item.InnerText
        }

        [PSCustomObject]@{
            TimeCreated  = $event.TimeCreated
            EventId      = $event.Id
            RuleName     = $data.RuleName
            EventType    = $data.EventType
            Process      = $data.Image
            ProcessId    = $data.ProcessId
            ProcessGuid  = $data.ProcessGuid
            TargetObject = $data.TargetObject
            Details      = $data.Details
        }
    } | Format-List

# Optional: set a ProcessGuid copied from a verified event before attempting correlation.
# An empty result means no matching event was found in this file; it does not prove absence.
