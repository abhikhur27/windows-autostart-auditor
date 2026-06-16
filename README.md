# Windows Autostart Auditor

Practical C# command-line utility that inventories Windows autostart surfaces so you can review what launches at login before the machine gets noisy, slow, or suspicious.

## What it scans

- `HKCU` and `HKLM` `Run` / `RunOnce` registry keys
- Current-user and all-users Startup folders
- Scheduled tasks visible through `schtasks /Query /FO CSV /V`

## What it reports

- consolidated autostart inventory across the common Windows launch surfaces
- missing or stale targets
- script-host launches (`powershell`, `cmd`, `wscript`, `cscript`)
- network-path launches
- entries rooted in temp or downloads paths
- sortable risk scores so the first cleanup pass starts where it matters

## Usage

```bash
dotnet run -- --json-out reports/audit.json --markdown-out reports/audit.md
```

## Output

- console summary with the highest-risk entries first
- JSON export for later scripting or diffing
- Markdown export for a human-readable cleanup brief

## Why this is useful

Autostart state is spread across several Windows surfaces. This tool turns that into one reviewable inventory you can use for:

- post-install cleanup
- suspicious-startup review
- performance triage on cluttered Windows machines
- documenting baseline startup state before you change services or scheduled tasks

## Verification

```bash
dotnet build
dotnet run -- --json-out reports/self-check.json --markdown-out reports/self-check.md
```

## Portfolio Positioning

- Project type: C# / .NET Windows CLI utility
- Target workflow: Windows startup hygiene and workstation audit
- Direction fit: practical native-ish Windows tooling rather than another browser demo
