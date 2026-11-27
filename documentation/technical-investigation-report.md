# Technical Investigation Report – Sysmon Lab 4.1

## Executive summary

Three EVTX datasets were examined using Sysmon event data and PowerShell. The investigations covered USB-related activity, a Run registry modification, and a suspicious CHM/HTA execution chain.

The evidence identified a SanDisk U3 Cruzer Micro device in registry telemetry, a Run-key value modification by `a.exe`, and a process chain involving `hh.exe` and `cmd.exe` with a command line that attempted external content retrieval and execution. The evidence does not establish a confirmed malicious file transfer, subsequent persistence execution, or successful download and execution of remote code.

## Scope and method

The analysis used:

- `USBCalc.evtx`
- `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`
- `Sysmon_Exec_CompiledHTML.evtx`

PowerShell `Get-WinEvent` was used to read event records. Sysmon event XML was parsed to extract named fields. Events were filtered by Event ID, process identifiers, and time windows. A process analysis export was also validated through CSV re-import.

## Finding 1 – USB-related activity

### Observations

Event distribution in `USBCalc.evtx`:

| Event ID | Description | Count |
|---:|---|---:|
| 1 | Process Create | 3 |
| 3 | Network Connection | 1 |
| 5 | Process Terminated | 1 |
| 9 | Raw Access Read | 4 |
| 13 | Registry Value Set | 2 |

Event ID 13 included registry paths identifying a SanDisk U3 Cruzer Micro device. Event ID 9 records showed raw access involving `\Device\HarddiskVolume3`, with `explorer.exe` and `svchost.exe` listed among the processes.

Process Create events around 2018-03-06 07:57:45–07:58:00 included:

- `WUDFHost.exe`, parent `svchost.exe`
- `rundll32.exe`, parent `explorer.exe`
- `calc.exe`, parent `rundll32.exe`

Event ID 5 recorded termination of the `rundll32.exe` process with Process ID 4024.

### Assessment

USB-related registry and process/disk activity was identified. The available evidence does not prove a specific file transfer or establish that `calc.exe` was malicious. The volume identifier should not be asserted to be the identified USB device without additional volume-to-device correlation.

## Finding 2 – Run-key persistence

### Observations

The persistence EVTX contained one Event ID 13. The event recorded:

| Field | Value |
|---|---|
| RuleName | Persistence - Hidden Run value detected |
| EventType | SetValue |
| Process | `C:\Users\Public\tools\evasion\a.exe` |
| Process ID | 3728 |
| TargetObject | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` |
| Details | `"c:\windows\tasks\taskhost.exe"` |

A Process Create lookup using a GUID recorded in the notes returned no matching event.

### Assessment

The registry modification is strongly consistent with an attempt to establish persistence through a Run key. The event does not prove the referenced file existed or executed at a later logon. The ProcessGuid lookup cannot establish process absence because the GUID used may not have matched the relevant event.

## Finding 3 – CHM/HTA execution

### Observations

The CHM/HTA EVTX contained two Event ID 1 Process Create events. The process relationship recorded in the lab was:

```text
explorer.exe
└── hh.exe
    └── cmd.exe
        └── attempted launch of %TEMP%\out.exe
```

The HTML Help process was launched with:

```text
"C:\Windows\hh.exe" C:\Users\IEUser\Desktop\Fax Record N104F.chm
```

The `cmd.exe` command line included instructions to copy `rundll32.exe` to `%TEMP%\out.exe`, invoke JavaScript through `mshtml,RunHTMLApplication`, create a `WinHttpRequest` object, request content from a raw Pastebin URL, and call `eval()` on returned content. A `taskkill` instruction targeting `out.exe` was also present.

The analyst searched the same EVTX file for Event IDs 3, 11, and 22 between 2019-07-26 09:39:10 and 09:39:20. No matching events were returned.

### Assessment

The process chain and command line provide strong evidence of a suspicious CHM-based execution attempt and attempted retrieval of external content. The available events do not confirm that the request succeeded, that the returned content executed, or that additional files were created.

## Overall assessment

| Area | Finding | Confidence boundary |
|---|---|---|
| USB | SanDisk U3 Cruzer Micro identified in registry data; related process and raw-access events observed | USB-related activity supported; no confirmed file transfer |
| Persistence | Run registry value modified by `a.exe` | Persistence attempt strongly indicated; later execution unverified |
| CHM/HTA | `hh.exe` launched `cmd.exe` with suspicious command-line logic | Execution attempt strongly indicated; successful infection unconfirmed |

## Limitations

- The analysis is limited to the three supplied EVTX files and retained lab notes.
- The USB event set does not prove data transfer.
- The persistence event does not prove later execution.
- The HTA/CHM event set does not prove successful external retrieval or execution.
- The time-bounded search did not return Event IDs 3, 11, or 22 in the specified window, but this does not rule out activity elsewhere.
- The ProcessGuid lookup did not return a match for the specific GUID used.

## Conclusion

The lab demonstrated how Sysmon event records can be used to reconstruct endpoint activity through process ancestry, registry telemetry, device-related information, event timestamps, and XML field extraction. The most suspicious behavior was the CHM/HTA process chain and command line; the strongest persistence evidence was the Run-key value modification. Conclusions remain constrained to the recorded evidence.
