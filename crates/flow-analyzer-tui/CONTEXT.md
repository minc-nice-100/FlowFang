# flow-analyzer-tui — Domain Glossary

The terminal UI dashboard. A standalone binary that connects to the analyzer's HTTP API and renders a real-time traffic audit display.

## Glossary

### TUI Dashboard

A terminal-based interactive display built with Ratatui. Shows:
- Real-time traffic rate (pps, bps)
- Top-N active flows
- Active fingerprint rules and their hit counts
- Recent alerts and events
- Keyboard shortcuts for interaction

### Ratatui

A Rust library for building terminal user interfaces. Provides widgets (tables, charts, gauges), layout management, and event handling. The TUI uses Ratatui to render the dashboard in a terminal.

### HTTP API Consumer

The TUI does not access shared memory directly — it connects to the analyzer's HTTP API (via Unix socket or TCP). It polls `/api/stats` for metrics and opens an SSE connection to `/api/events` for real-time alerts. This keeps the TUI decoupled from the analyzer's internal state.

### Keyboard Shortcuts

Interactive controls for the dashboard:
- `q` / `Esc` — quit
- `f` — view fingerprints
- `s` — view stats detail
- `a` — add a fingerprint (opens a prompt)
- `d` — delete selected fingerprint
- `↑↓` — scroll through lists
- `Tab` — switch panels

### Dashboard Panels

The TUI screen is divided into panels:
- **Header** — system name, version, uptime
- **Stats** — pps, bps, active flows, fingerprint hits
- **Top Flows** — sorted table of top-N flows by packet count
- **Fingerprints** — active rules with match counts
- **Alerts** — recent SSE events (scrolling log)