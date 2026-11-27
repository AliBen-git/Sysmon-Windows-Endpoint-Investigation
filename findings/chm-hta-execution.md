# Finding 3 – CHM / HTA Suspicious Execution

**Dataset:** `Sysmon_Exec_CompiledHTML.evtx`

## Observed process chain

The two Process Create (Event ID 1) events supported this chain:

```text
explorer.exe
└── hh.exe "C:\Users\IEUser\Desktop\Fax Record N104F.chm"
    └── cmd.exe
        └── attempted launch of %TEMP%\out.exe
```

The original file was `Fax Record N104F.chm`, opened using Windows HTML Help (`hh.exe`).

## Command-line behavior

The `cmd.exe` command line included:

1. Copying `rundll32.exe` to `%TEMP%\out.exe`.
2. Attempting to start the copied binary using a JavaScript / `mshtml,RunHTMLApplication` technique.
3. Creating a `WinHttpRequest` object.
4. Attempting to retrieve content from a raw Pastebin URL.
5. Using `eval()` on the returned content.
6. Including a `taskkill` command targeting `out.exe`.

## Additional validation

The lab queried Sysmon Event IDs 3 (Network Connection), 11 (File Create), and 22 (DNS Query) between 2019-07-26 09:39:10 and 09:39:20 in the supplied EVTX file. No matching events were returned.

## Assessment

The process chain and command line provide strong evidence of a suspicious CHM-based execution attempt and attempted external content retrieval.

The two Process Create events do not prove that the download succeeded, that remote code executed, or that additional files were created. The absence of matching events in the queried EVTX time window does not prove that these activities never occurred.
