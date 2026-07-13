# Issue Tracker

## Provider

**GitHub Issues** — all issues are tracked in the repo's GitHub Issues.

## CLI

The `gh` CLI must be installed and authenticated. Commands use the form:

```
gh issue create --title "..." --body "..." --label "foo,bar"
gh issue list --label "needs-triage" --json number,title,body,labels
gh issue edit <number> --add-label "foo" --remove-label "bar"
```

## External PRs as a triage surface

**Enabled.** External pull requests are treated as issues for triage purposes. The `/triage` skill pulls open external PRs into the same queue and runs them through the same labels and states as issues.

Collaborators' in-flight PRs are excluded — only PRs opened by non-collaborators are surfaced.