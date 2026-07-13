# Triage Labels

The five canonical triage labels use the default vocabulary. No overrides.

| Canonical role     | GitHub label      |
|--------------------|-------------------|
| needs-triage       | `needs-triage`    |
| needs-info         | `needs-info`       |
| ready-for-agent    | `ready-for-agent`  |
| ready-for-human    | `ready-for-human`  |
| wontfix            | `wontfix`          |

## State machine

```
incoming → needs-triage → ready-for-agent → done
                        → ready-for-human → done
                        → needs-info → needs-triage
                        → wontfix
```