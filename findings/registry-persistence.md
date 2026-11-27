# Finding 2 – Run Registry Persistence

**Dataset:** `evasion_persis_hidden_run_keyvalue_sysmon_13.evtx`

## Observed event

One Sysmon Event ID 13 (Registry Value Set) was recorded.

| Field | Observed value |
|---|---|
| RuleName | Persistence - Hidden Run value detected |
| EventType | SetValue |
| Process | `C:\Users\Public\tools\evasion\a.exe` |
| Process ID | 3728 |
| TargetObject | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\` |
| Details | `"c:\windows\tasks\taskhost.exe"` |
| Event date in lab notes | 2020-07-04 |

## Analysis

The Windows Run registry location is used to configure programs that start automatically at logon. The event records `a.exe` setting a value beneath this location to point to `c:\windows\tasks\taskhost.exe`.

This is strongly consistent with an attempt to establish persistence.

## Correlation limitation

A Process Create lookup was attempted using a ProcessGuid recorded in the lab notes, but no matching event was returned. The notes identify a likely GUID selection/copying issue as a possible explanation. The failed lookup does not prove the process was absent.

## Assessment

The registry value modification is observed. The existence of the referenced file and its later execution at logon were not verified.
