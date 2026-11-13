# Firewall Analysis Report

## 1. Summary

- **Total Rules Analyzed:** 6
- **Enabled Rules Analyzed:** 4
- **Analysis Duration:** 2 ms

| Category | Count |
|---|---:|
| Shadowed (Same Action) | 1 |
| Duplicates | 1 |
| Conflicts | 3 |
| Partial Overlaps | 1 |
| Disabled Rules | 1 |

## 3. Duplicates

Displaying top 1 findings.

| Rule | Duplicate Of | Slot |
|---|---|---|
| allow_web_from_lan_copy | allow_web_from_lan | filter |

## 4. Conflicts

Displaying top 3 findings.

| Rule A | Rule B | Slot |
|---|---|---|
| block_lan_to_servers | allow_web_from_lan | filter |
| block_lan_to_servers | allow_http_from_admin | filter |
| block_lan_to_servers | allow_web_from_lan_copy | filter |

## 5. Shadowed Rules (Same Action)

Displaying top 1 findings.

| Rule | Shadowed By | Slot |
|---|---|---|
| allow_http_from_admin | allow_web_from_lan | filter |

## 6. Partial Overlaps

Displaying top 1 findings.

| Rule A | Rule B | Slot |
|---|---|---|
| allow_web_from_lan_copy | allow_http_from_admin | filter |

## 7. Disabled Rules

```
legacy_any_any
```

