# Finding 1 – USB Activity

**Dataset:** `USBCalc.evtx`

## Recorded event counts

| Event ID | Sysmon event | Count |
|---:|---|---:|
| 1 | Process Create | 3 |
| 3 | Network Connection | 1 |
| 5 | Process Terminated | 1 |
| 9 | Raw Access Read | 4 |
| 13 | Registry Value Set | 2 |

## Observations

Event ID 13 registry information identified a SanDisk U3 Cruzer Micro device. The registry path included a USBSTOR reference and a FriendlyName value.

Event ID 9 recorded raw access involving `\Device\HarddiskVolume3`. The processes listed included `explorer.exe` and `svchost.exe`.

Process Create events around 2018-03-06 07:57:45–07:58:00 included:

| Process | Parent process | Approx. time |
|---|---|---|
| `WUDFHost.exe` | `svchost.exe` | 07:57:48 |
| `rundll32.exe` | `explorer.exe` | 07:57:51 |
| `calc.exe` | `rundll32.exe` | 07:57:51 |

Event ID 5 recorded termination of `rundll32.exe` (PID 4024).

## Assessment

The records identify USB-related registry information and associated process/disk activity. They can support reconstruction of activity around the device.

They do **not** prove that a specific file was copied. The available data also does not prove that `calc.exe` was malicious. The volume identifier should not be assumed to map to the SanDisk device without further device-to-volume correlation.
