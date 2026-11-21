# Detection as Code

Windows threat detections written once in [Sigma](https://github.com/SigmaHQ/sigma), tested like software, and converted automatically into Splunk, Microsoft Sentinel / Defender XDR and Elastic queries.

Every rule in this repo:

1. is mapped to MITRE ATT&CK,
2. is proven to **fire** on real attack style events and stay **silent** on normal activity (unit tests),
3. ships with a triage playbook an L1 analyst can follow,
4. is validated and converted on every push by GitHub Actions.

## How it works

```
rules/*.yml  ──►  pytest (engine/matcher.py)  ──►  sigma check  ──►  scripts/convert_all.py  ──►  queries/
 Sigma rules       fires on malicious samples      spec and          Splunk SPL, Sentinel KQL,
                   silent on benign samples        ATT&CK checks     Defender XDR KQL, Elastic
```

## Rules

| Rule | ATT&CK | Level | Playbook |
| --- | --- | --- | --- |
| [Windows Security Audit Log Cleared](rules/windows/security/win_security_audit_log_cleared.yml) | T1070.001 Clear Windows Event Logs | High | [triage](docs/playbooks/win_security_audit_log_cleared.md) |
| [Member Added To A Privileged Windows Group](rules/windows/security/win_security_privileged_group_member_added.yml) | T1098 Account Manipulation | High | [triage](docs/playbooks/win_security_privileged_group_member_added.md) |
| [PowerShell Started With An Encoded Command](rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml) | T1059.001 PowerShell, T1027 Obfuscation | Medium | [triage](docs/playbooks/proc_creation_win_powershell_encoded_command.md) |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest -v                       # test every rule against its samples
sigma check rules/              # validate against the Sigma spec (needs internet for ATT&CK data)
python scripts/convert_all.py   # write SIEM queries to queries/
```

## Repo layout

```
rules/                     Sigma rules, grouped by log source
tests/fixtures/<rule>/     malicious.json and benign.json sample events for each rule
tests/test_rules.py        every rule must fire on malicious and stay silent on benign
tests/test_metadata.py     every rule needs ATT&CK tags, a level, false positives, a valid id
engine/matcher.py          small Sigma evaluator used by the tests
pipelines/                 custom field and table mappings (Sentinel SecurityEvent)
scripts/convert_all.py     converts rules into Splunk, KQL and Elastic queries
docs/playbooks/            triage steps for each rule
queries/                   generated queries (rebuilt by CI)
```

## Adding a rule

1. Write the rule in `rules/<log source>/` (copy an existing one for the layout and generate a new UUID for `id`).
2. Add at least one `malicious.json` and one `benign.json` event in `tests/fixtures/<rule file name>/`. Include a tricky benign case that looks close to the attack.
3. Run `pytest -v` until it passes.
4. Write the triage playbook in `docs/playbooks/`.
5. Run `python scripts/convert_all.py`, add the row to the table above, and push.

## About the sample events

The first samples are hand written from Microsoft's documented event fields. Week 2 of the [roadmap](ROADMAP.md) adds real recorded attack logs from public datasets such as the [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) and [EVTX attack samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

## Author

Phranavh Sivaraman · [LinkedIn](https://linkedin.com/in/phranavhsivaraman) · [Portfolio](https://phranavh.vercel.app)
