# Playbook: Windows Security Audit Log Cleared

**Rule:** `win_security_audit_log_cleared` · **ATT&CK:** T1070.001 Clear Windows Event Logs · **Severity:** High

## What it means

Someone cleared the Security event log (Event ID 1102). Legitimate clears are rare and planned. Attackers clear the log to hide logons, privilege use and process execution, so treat this as a sign that something else already happened on the host.

## Triage

1. **Who cleared it?** Note `SubjectUserName` and `SubjectDomainName`. Is it an admin who would do this, a service account, or a normal user?
2. **Was it planned?** Check change tickets and maintenance windows for this host.
3. **What happened before?** Look at the 2 hours before the clear on this host in other sources that were not wiped: EDR, Sysmon, firewall, proxy, the domain controller's logs and your SIEM (events already forwarded are safe).
4. **Where else?** Search for 1102 on other hosts in the same period. Several hosts cleared close together suggests an active intrusion.
5. **How did they get in?** Check logons by the same account (4624 logon types 3 and 10) across the estate.

## Escalate to L2 when

- The account is not an approved admin, or there is no change ticket
- Suspicious activity appears before the clear (new services, scheduled tasks, encoded PowerShell, unusual logons)
- More than one host was cleared

## Close as benign when

- A documented change ticket covers the host, the account and the time, and nothing suspicious appears before it

## Response actions (with L2 approval)

- Isolate the host with EDR
- Reset the credentials of the account that cleared the log
- Preserve forwarded logs and EDR telemetry for the investigation
