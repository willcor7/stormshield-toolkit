# Stormshield SNS rule analyzer

Reads a firewall policy exported as CSV and reports rules that are redundant or contradict each other. It works offline, without Stormshield Management Center, and uses only the Python standard library.

## What it reports

- **Shadowed rules**: a rule whose matching criteria are fully covered by an earlier rule with the same action.
- **Duplicates**: a rule identical to an earlier one (same criteria, same action).
- **Conflicts**: a rule that overlaps an earlier rule but has a different action (for example `pass` against `block`).
- **Partial overlaps**: a rule that overlaps an earlier rule with the same action without being fully covered by it.
- **Disabled rules** and **unknown objects**, listed separately.

## Usage

```bash
python detect_stormshield_anomalies.py \
  --rules ../examples/rules/rules.csv \
  --objects ../examples/rules/objects.csv \
  --out report.json --md report.md
```

The report produced from the sample files is in [`../examples/rules/sample_report.md`](../examples/rules/sample_report.md).

## Input files

### Rules (required)

A CSV file, comma or semicolon separated (detected automatically), UTF-8. Header names may start with `#`, as in SNS exports. Only lines whose `type_slot` is `rule` are analyzed; separators are skipped.

| Column | Meaning |
|---|---|
| `type_slot` | `rule` for a rule line; any other value is ignored |
| `rule_name` | Rule identifier used in the report |
| `state` | `on`, `active`, `enabled` or `true` for an enabled rule; anything else is treated as disabled |
| `action` | Rule action, for example `pass` or `block` |
| `from_src` | Source: IP, network, range or object name; several values separated by commas |
| `to_dest` | Destination, same syntax |
| `service` | Port, port range, or service object name |
| `proto` | Protocol: `tcp`, `udp`, `any` |
| `comment` | Free text |
| `nat_to_target` | Optional; when filled, the line is treated as a NAT rule |

### Objects (optional)

A CSV file with three columns, used to resolve object names found in the rules.

| Column | Meaning |
|---|---|
| `name` | Object name |
| `type` | `host`, `network`, `range`, `group`, `service` or `service_group` |
| `value` | CIDR, IP range, `proto:port`, or a comma-separated list of members for groups |

## Options

| Option | Default | Meaning |
|---|---|---|
| `--rules PATH` | required | Rules CSV file |
| `--objects PATH` | none | Objects CSV file |
| `--out PATH` | required | JSON report |
| `--md PATH` | none | Markdown report |
| `--slot filter\|nat\|both` | `both` | Which rules to analyze |
| `--ipv6 on\|off` | `off` | Process IPv6 addresses |
| `--unknown fail\|warn` | `warn` | Stop, or continue with a warning, when a rule uses an unknown object |

## Tests

```bash
python -m unittest test_detector
```

## Limits

- The comparison is quadratic in the number of rules, so very large policies (above roughly 10,000 rules) take longer.
- NAT rules are compared on their matching criteria only; the translation itself is not analyzed.
- "Shadowed" means covered by a rule placed earlier in the policy.
