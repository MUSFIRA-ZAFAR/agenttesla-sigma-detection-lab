# Indicators of Compromise — Agent Tesla Sample

Extracted from ANY.RUN interactive sandbox analysis. All values confirmed directly from raw sandbox telemetry (process list, registry/file activity, network connections, and built-in Suricata IDS threat detection) — none inferred or assumed.

## File Indicators

| Field | Value |
|---|---|
| File name (as detonated) | `708e198608b5b463224c3fb77fcf708b845d0c7b5dbc6e9cab9e185c489be089.exe` |
| SHA256 | `708e198608b5b463224c3fb77fcf708b845d0c7b5dbc6e9cab9e185c489be089` |
| MD5 | `F7149D36C5941E1D4BAD59C2CC451D37` |
| File type | PE32 executable (GUI), .NET assembly |
| Malware family | Agent Tesla |
| Classification | Infostealer / Keylogger |
| Delivery | Password-protected `.zip` archive (AV evasion) |

## Persistence Indicators

| Field | Value |
|---|---|
| Technique | Scheduled Task creation |
| MITRE ATT&CK | T1053.005 |
| Creating binary | `schtasks.exe` |
| Parent process location | `%TEMP%` (disguised filename) |
| Task path/name | `Updates\neHneiobyhcrJJ` |
| Task XML staging path | `%TEMP%\tmp77E5.tmp` |

## Network / C2 Indicators

| Field | Value |
|---|---|
| Technique | Application Layer Protocol — Mail (SMTP exfiltration) |
| MITRE ATT&CK | T1071.003 |
| C2 domain | `godforeu.com` |
| C2 IP (A record) | `34.41.139.193` |
| C2 IP (AAAA record) | `2600:1900:4001:96e:8000:1:644b:eff1` |
| Port | `587` |
| Protocol | SMTP (disguised as legitimate outbound mail) |
| IDS confirmation | Suricata rule SID `84003451` — "STEALER [ANY.RUN] AgentTesla CnC Domain (godforeu.com)" |

## Live Status Note

At the time of this analysis, `godforeu.com` still actively resolved via public DNS — the C2 infrastructure had not been sinkholed or taken down. This was independently re-confirmed on the lab's isolated AWS VM via a safe, connection-free `Resolve-DnsName` lookup.
