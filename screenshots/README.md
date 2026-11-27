# Screenshot Evidence

This directory contains seven PowerShell screenshots from **Lab 4.1 – Sysmon Investigations**. The filenames match the image references in the root README.

| File | Evidence shown | Investigation |
|---|---|---|
| [01-evtx-inventory.png](01-evtx-inventory.png) | EVTX inventory and event counts | Evidence overview |
| [02-usb-registry-event.png](02-usb-registry-event.png) | Registry data identifying the SanDisk U3 Cruzer Micro | USB activity |
| [03-usb-raw-access.png](03-usb-raw-access.png) | Sysmon Event ID 9 raw access records | USB activity |
| [04-registry-persistence.png](04-registry-persistence.png) | Event ID 13 Run-key modification by `a.exe` | Persistence |
| [05-chm-process-chain.png](05-chm-process-chain.png) | Explorer, `hh.exe`, and `cmd.exe` process relationship | CHM/HTA execution |
| [06-suspicious-command-line.png](06-suspicious-command-line.png) | Suspicious command-line sequence and retrieval logic | CHM/HTA execution |
| [07-csv-export-validation.png](07-csv-export-validation.png) | CSV export and validation workflow | Investigation workflow |

Screenshots support the written findings. They should not be interpreted as proof of successful file transfer, persistence execution, successful download, or remote code execution unless corroborating telemetry establishes those outcomes.
