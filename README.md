# Stormshield Toolkit

Python tools that automate repetitive work on Stormshield Network Security (SNS) firewalls: preparing filter and NAT rules, reviewing a policy for inconsistencies, turning logs into flows, and extracting IPsec VPN configuration.

They were written for day-to-day firewall operations where the same tasks come back every week and a typo in a rule has real consequences. Every tool produces a file a human reviews before anything is applied to a firewall.

All sample data in this repository is fictitious (private and documentation IP ranges, invented host names).

## What is in the repository

| Folder | Tool | What it does |
|---|---|---|
| [`suite/`](suite/) | Interactive suite | One menu for five tasks: analyze logs, export objects and interfaces over SSH, convert CSV rules to SNS CLI (NSRPC) commands, compare two rule sets, detect duplicate rules. |
| [`rule_analyzer/`](rule_analyzer/) | Rule analyzer | Reads a policy exported as CSV and reports shadowed rules, duplicates, conflicts and partial overlaps. Standard library only. |
| [`vpn_extractor/`](vpn_extractor/) | IPsec VPN extractor | Reads active tunnels and peer settings from a firewall and writes a JSON file prepared for import into Stormshield Management Center (SMC). |
| [`examples/`](examples/) | Sample data | Fictitious logs, rules and objects, with the output each tool produces from them. |

## Quick start

Python 3.8 or later.

```bash
git clone https://github.com/willcor7/stormshield-toolkit.git
cd stormshield-toolkit
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Review a policy for inconsistencies

No firewall access needed; this runs on the sample files.

```bash
cd rule_analyzer
python detect_stormshield_anomalies.py \
  --rules ../examples/rules/rules.csv \
  --objects ../examples/rules/objects.csv \
  --out report.json --md report.md
```

The result on the sample policy ([full report](examples/rules/sample_report.md)):

| Category | Count |
|---|---:|
| Shadowed (same action) | 1 |
| Duplicates | 1 |
| Conflicts | 3 |
| Partial overlaps | 1 |
| Disabled rules | 1 |

### Run the interactive suite

```bash
cd suite
python main.py
```

Option 1 (log analysis) works on `examples/logs/sample_logs.csv`. It groups log lines into unique flows (source, destination, service) and writes a detailed CSV plus a summary of the top flows, which is the starting point for writing the right rule. Options 2 to 5 are described in [`suite/README.md`](suite/README.md).

### Extract IPsec VPN configuration

```bash
cd vpn_extractor
python sns_vpn_extractor.py --host <firewall-ip> --user <admin-user>
```

The password is asked interactively. See [`vpn_extractor/README.md`](vpn_extractor/README.md).

## How the rule conversion stays safe

The CSV to CLI converter does not push anything to a firewall. It checks each rule against the objects and interfaces exported from the target firewall and splits the result into three files:

- `rules_safe.txt`: commands for rules whose dependencies all exist;
- `rules_pending.txt`: rules held back, with the reason;
- `dependencies_missing.txt`: the objects and interfaces to create first.

An engineer reads the generated script before running it. Samples of these files are in [`examples/suite_output/`](examples/suite_output/).

## Tests

```bash
cd rule_analyzer && python -m unittest test_detector
cd ../vpn_extractor && python -m unittest discover -s tests
```

The tests use inline sample data and mocks; they do not need a firewall.

## Good practice when using these tools

- Do not commit real exports, logs or generated scripts: they describe a production network. The `.gitignore` excludes the default output folders.
- Leave the password empty in `suite/config.ini`; the tools prompt for it.
- Run generated scripts on a test or standby firewall first when you can.

## Status

Working tools, used in operations, shared as they are. The suite keeps its logic in a single module (`suite/tool_functions.py`); splitting it into smaller modules with their own tests is the next cleanup step.

This project is independent and is not affiliated with or endorsed by Stormshield.
