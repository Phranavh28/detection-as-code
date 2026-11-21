# 8 week roadmap

About 1 hour on work nights and 3 to 4 hours on weekends. Tick items off as you go. Rule of the project: nothing new starts until the week before it is done and pushed.

## Week 1: Foundations (this starter)

- [x] Repo structure, 3 Sigma rules, sample events, tests, converter, CI
- [ ] Create the GitHub repo `detection-as-code` and push this code
- [ ] Watch the first GitHub Actions run go green and download the `siem-queries` artifact
- [ ] Read every line of `engine/matcher.py` until you can explain how a condition is evaluated
- [ ] Read the [Sigma rule specification](https://github.com/SigmaHQ/sigma-specification) (rules section)

## Week 2: Real attack data

- [ ] Clone the [EVTX attack samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) and the [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) into `datasets/raw/` (ignored by Git)
- [ ] Write `scripts/evtx_to_json.py` that turns .evtx files into flat JSON events (python-evtx library)
- [ ] Find a real 1102, 4728 / 4732 and encoded PowerShell event in the datasets and add them to the fixtures
- [ ] Run all 3 rules over a whole dataset and count hits: are there any false positives?

## Week 3: Credential attacks (4 new rules)

- [ ] Kerberoasting: 4769 with ticket encryption type 0x17 (RC4) for a service account
- [ ] Logon attempts against nonexistent or disabled accounts (4625 with Status 0xC0000064 or 0xC0000072), a common spraying signal
- [ ] LSASS memory access (Sysmon Event 10, TargetImage lsass.exe)
- [ ] New user account created (4720), with a filter for your known provisioning accounts

## Week 4: Persistence (4 new rules)

- [ ] Scheduled task created (4698) with a suspicious command
- [ ] New service installed (7045) from a user writable path
- [ ] Registry Run key set (Sysmon Event 13)
- [ ] WMI event subscription (Sysmon Events 19 to 21)

## Week 5: Correlation and tuning

- [ ] Learn Sigma correlation rules (event count, value count, temporal)
- [ ] Write a brute force correlation rule: 10+ 4625 from one source in 5 minutes
- [ ] Add a `filter_` to one rule to remove a known false positive, with a benign sample that proves it
- [ ] Add the `windash` modifier to the encoded PowerShell rule so `/enc` and other dash styles are caught

## Week 6: Run it in a real SIEM

- [ ] Free option: Splunk Free or Elastic on your laptop (Docker), or a Microsoft Sentinel trial
- [ ] Load one real dataset, paste the converted queries, confirm they return the expected events
- [ ] Record any field name differences and fix them in `pipelines/`

## Week 7: Coverage and reporting

- [ ] Generate an ATT&CK Navigator layer from the rule tags (`scripts/attack_layer.py`) and add the picture to the README
- [ ] Add a status badge for the CI workflow to the README
- [ ] Aim for 15 to 20 rules in total

## Week 8: Publish

- [ ] Write a blog post on phranavh.vercel.app: "How I test detections like software"
- [ ] One LinkedIn post with the ATT&CK coverage picture and the repo link
- [ ] Add the project to your resume Projects section with real numbers (rules, techniques covered, tests)
