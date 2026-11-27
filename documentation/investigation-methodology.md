# Investigation Methodology

## Evidence sources

The lab used three supplied Windows Event Log files:

- `USBCalc.evtx`
- `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`
- `Sysmon_Exec_CompiledHTML.evtx`

The original working directory was referenced through a PowerShell variable named `$evidence`. The lab also used `$persistenceEvtx`, `$htaEvtx`, and a `$guid` variable for targeted lookups. These variables must be assigned to valid paths or identifiers before running the examples.

## 1. Evidence inventory

The analyst first verified that the exported CSV existed with `Test-Path`, then inventoried EVTX files using `Get-ChildItem`.

## 2. Event ID distribution

The files were read with `Get-WinEvent` and grouped by `Id` using `Group-Object`. This established which event types were available before deeper analysis.

## 3. XML field extraction

Each event was converted to XML using `[xml]$event.ToXml()`. The `EventData.Data` nodes expose named fields. A hashtable can be populated dynamically with each field's `Name` attribute and `InnerText` value, then projected into a `[PSCustomObject]` for analysis.

Important fields included:

- `Image`
- `CommandLine`
- `ParentImage`
- `ProcessGuid`
- `ParentProcessGuid`
- `TargetObject`
- `Details`
- `Device`
- `Hashes`

## 4. USB activity

In `USBCalc.evtx`, Event IDs 13, 9, 1, and 5 were examined. Registry values identified SanDisk U3 Cruzer Micro device information; raw access, process creation, and process termination events were reviewed in the same time window.

The analysis did not establish a specific file copy. The event data supports a description of USB-related activity, not proof of data transfer.

## 5. Persistence

The persistence dataset contained one Event ID 13. The analyst extracted the process, registry target, new value, ProcessGuid, and timestamp. A separate Process Create lookup was attempted with a ProcessGuid. The supplied notes report no matching result for the GUID used; this is a limitation of that lookup and must not be overstated.

## 6. CHM/HTA process analysis

The CHM/HTA dataset contained two Event ID 1 events. The analyst extracted process image, command line, parent process, process GUIDs, and hashes to reconstruct the process chain from Explorer through HTML Help and command shell execution.

## 7. Time-bounded validation

A search was made for Event IDs 3, 11, and 22 in a ten-second interval around the suspicious activity. No matches were returned in the supplied EVTX file. This only describes the scope and result of that query; it does not rule out activity in another time window or log source.

## 8. CSV export and validation

The process analysis was exported as `Investigation-HTA-ProcessAnalysis.csv` using `Export-Csv`. `Test-Path` returned `True`, and `Import-Csv` successfully read the file.

## Evidence handling principles

- Separate direct observations from analytical interpretation.
- Do not infer successful execution from a command line that only shows an attempt.
- Do not infer file transfer from USB registry and raw-access events alone.
- Do not infer persistence execution from a Run-key modification alone.
- Treat missing events as missing from the queried file and time window, not as proof that activity did not occur.
