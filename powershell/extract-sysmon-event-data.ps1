param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvtxPath,

    [Parameter(Mandatory = $true)]
    [int]$EventId
)

Get-WinEvent -Path $EvtxPath -ErrorAction Stop |
    Where-Object { $_.Id -eq $EventId } |
    ForEach-Object {
        $event = $_
        [xml]$xml = $event.ToXml()

        $fields = [ordered]@{
            TimeCreated = $event.TimeCreated
            EventId     = $event.Id
        }

        foreach ($item in $xml.Event.EventData.Data) {
            $name = $item.GetAttribute("Name")
            if ($name) {
                $fields[$name] = $item.InnerText
            }
        }

        [PSCustomObject]$fields
    }
