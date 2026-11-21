# Playbook: PowerShell Started With An Encoded Command

**Rule:** `proc_creation_win_powershell_encoded_command` · **ATT&CK:** T1059.001 PowerShell, T1027 Obfuscated Files or Information · **Severity:** Medium

## What it means

PowerShell was started with a Base64 encoded command. Some admin tools do this legitimately, but it is also one of the most common ways malware, phishing documents and attackers hide what they run.

## Triage

1. **Decode the command.** Copy the Base64 string from `CommandLine` and decode it as UTF 16LE (CyberChef: "From Base64" then "Decode text, UTF 16LE"). Never run it.
2. **Read what it does.** Red flags: downloads (`Net.WebClient`, `Invoke-WebRequest`, `DownloadString`), `IEX` / `Invoke-Expression`, hidden windows, disabling Defender, connections to IPs or new domains.
3. **Check the parent process.** `ParentImage` of Word, Excel, Outlook, a browser, `wscript.exe` or `mshta.exe` is highly suspicious. A known management agent may be legitimate.
4. **Check the user and host.** Is this user expected to run scripts? Is it a server or a normal workstation?
5. **Look at what happened next.** Network connections, files written and child processes from this PowerShell process in EDR or Sysmon (Events 3 and 11).
6. **Enrich indicators.** Check any domains, IPs and file hashes in VirusTotal or your threat intelligence platform.

## Escalate to L2 when

- The decoded command downloads or runs code, or contacts an external address
- The parent is an Office application, browser or script host
- The binary was renamed (Image path does not end in powershell.exe or pwsh.exe)

## Close as benign when

- The parent and decoded content match a known, approved management tool, and the same pattern is documented. Suggest a filter for the rule so it stops alerting on that tool.

## Response actions (with L2 approval)

- Isolate the host with EDR
- Block any domains or IPs found in the decoded command
- Collect the decoded script and process tree for the incident record
