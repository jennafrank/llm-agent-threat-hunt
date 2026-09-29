# MITRE ATT&CK + ATLAS Mapping

## Hunt 24: TideGlass — Autonomous LLM-Agent Post-Exploitation

### ATT&CK Enterprise (v15)

| Tactic | Technique | Sub-Technique | Name | Finding | Detection |
|--------|-----------|---------------|------|---------|-----------|
| Initial Access | T1190 | — | Exploit Public-Facing Application | F1 | D1 |
| Execution | T1059 | .006 | Command and Scripting Interpreter: Python | F2 | D2 |
| Credential Access | T1552 | .005 | Unsecured Credentials: Cloud Instance Metadata API | F3 | D3 |
| Credential Access | T1552 | .004 | Unsecured Credentials: Private Keys | F5 | D5 |
| Credential Access | T1555 | .006 | Credentials from Password Stores: Cloud Secrets Manager | F5 | D5 |
| Defense Evasion | T1090 | — | Proxy | F4 | D4 |
| Persistence | T1078 | .004 | Valid Accounts: Cloud Accounts | F6 | D6 |
| Lateral Movement | T1021 | .004 | Remote Services: SSH | F6 | D6 |
| Collection | T1213 | .006 | Data from Information Repositories: Databases | F7 | D7 |
| Exfiltration | T1567 | .002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | F7 | D7 |

### Hunted, Not Observed

| Tactic | Technique | Name | Notes |
|--------|-----------|------|-------|
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | Exfiltration used HTTPS (T1567.002), not an alternative protocol |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | No persistent C2 channel; agent operated autonomously |

### MITRE ATLAS (v2026.09)

| Technique | Name | Maturity | Finding | Detection | Notes |
|-----------|------|----------|---------|-----------|-------|
| AML.T0098 | AI Agent Tool Credential Harvesting | Realized | F3, F8 | D8 | Agent used its own tool-calling to harvest cloud credentials via IMDS |

### ATLAS Mitigations

| Mitigation | Name | Applicability |
|------------|------|---------------|
| AML.M0032 | Segmentation of AI Agent Components | The agent's guardrail passed every action with "no policy matched" (F8); segmenting agent components and enforcing least-privilege on tool access would have blocked lateral movement |

---

### Attack Chain by Tactic

```
Initial Access ──► Execution ──► Credential Access ──► Defense Evasion
    T1190              T1059.006      T1552.005             T1090
    (marimo RCE)       (Python)       T1552.004          (egress pool)
                                      T1555.006
                                      AML.T0098
                                         │
                    ◄────────────────────┘
                    │
              Lateral Movement ──► Collection ──► Exfiltration
                  T1021.004          T1213.006      T1567.002
                  T1078.004          (Postgres)     (curl upload)
                  (SSH bastion)
```

---

*Mappings based on MITRE ATT&CK v15 and MITRE ATLAS v2026.09.*
