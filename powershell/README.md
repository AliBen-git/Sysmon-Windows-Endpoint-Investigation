# PowerShell Investigation Scripts

The scripts in this folder reproduce the analysis patterns documented in Lab 4.1 using the supplied EVTX evidence files.

## Before running

Set paths for the variables used by the scripts:

```powershell
$evidence = "C:\Path\To\Evidence"
$persistenceEvtx = Join-Path $evidence "evasion_persis_hidden_run_keyvalue_sysmon_13.evtx"
$htaEvtx = Join-Path $evidence "Sysmon_Exec_CompiledHTML.evtx"
```

Use copies of the original evidence files and preserve the originals. These scripts read event files and do not modify the EVTX evidence.

## Scripts

- `inventory-and-event-counts.ps1` – lists EVTX files and counts events by Event ID.
- `extract-sysmon-event-data.ps1` – extracts named fields from a selected event.
- `usb-investigation.ps1` – reviews USB-related Event IDs 1, 5, 9, and 13.
- `persistence-investigation.ps1` – extracts the Run-key modification from Event ID 13.
- `chm-process-investigation.ps1` – extracts process creation information and performs the documented time-window check.

## Important

These are reusable versions of the commands documented in the lab. They have not been executed against the original evidence by repository preparation. The findings in the reports are transcribed from the documented lab observations.
