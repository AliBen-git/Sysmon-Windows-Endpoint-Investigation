param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvtxPath
)

# Event ID 13: registry values that recorded SanDisk USB device information.
Get-WinEvent -LiteralPath $EvtxPath -FilterXPath "*[System[(EventID=13)]]" |
    ForEach-Object {
        $event = $_
        [xml]$xml = $event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.GetAttribute("Name")] = $item.InnerText
        }

        [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventId     = $event.Id
            Process     = $data.Image
            TargetObject = $data.TargetObject
            Details     = $data.Details
        }
    } | Format-List

# Event ID 9: raw access read events. Device-to-USB mapping requires separate validation.
Get-WinEvent -LiteralPath $EvtxPath -FilterXPath "*[System[(EventID=9)]]" |
    ForEach-Object {
        $event = $_
        [xml]$xml = $event.ToXml()
        $data = @{}
        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.GetAttribute("Name")] = $item.InnerText
        }

        [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            Process     = $data.Image
            ProcessId   = $data.ProcessId
            ProcessGuid = $data.ProcessGuid
            Device      = $data.Device
        }
    } | Format-Table -AutoSize -Wrap

# Event IDs 1 and 5: process creation and termination for the recorded timeline.
Get-WinEvent -LiteralPath $EvtxPath |
    Where-Object { $_.Id -in 1, 5 } |
    Sort-Object TimeCreated |
    Select-Object TimeCreated, Id, Message |
    Format-List
