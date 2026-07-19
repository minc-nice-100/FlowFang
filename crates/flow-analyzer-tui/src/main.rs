//! FlowFang TUI — terminal dashboard for the FlowFang traffic audit system.
//!
//! Connects to the analyzer's HTTP API to display real-time traffic
//! statistics, active fingerprint rules, and alerts.

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{Event as CtEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use flow_common::types::{DpiFingerprint, DpiPattern, ProcessorAction};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use serde::Deserialize;
use std::io;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

/// FlowFang TUI — terminal audit dashboard.
#[derive(Parser)]
#[command(name = "flow-analyzer-tui", version)]
struct Args {
    /// Analyzer API address (unix:// or tcp://, like Docker daemon)
    #[arg(short, long, default_value = "unix:///var/run/flowfang.sock")]
    connect: String,
}

// --- API response types ---

#[derive(Deserialize, Debug)]
struct StatusResponse {
    version: String,
    uptime_secs: u64,
    sampler_connected: bool,
}

#[derive(Deserialize, Debug)]
struct StatsResponse {
    total_packets: u64,
    total_bytes: u64,
    packets_per_second: f64,
    bytes_per_second: f64,
    active_flows: usize,
    top_flows: Vec<FlowInfo>,
}

#[derive(Deserialize, Debug, Clone)]
struct FlowInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    packets: u64,
    bytes: u64,
}

// --- Address parsing ---

/// Parsed analyzer address: the base URL plus an optional Unix socket path.
enum Addr {
    /// HTTP over a Unix domain socket. `base` is a dummy host used only to
    /// build well-formed request URIs; the socket path selects the peer.
    Unix { path: String, base: String },
    /// Plain HTTP over TCP.
    Tcp { base: String },
}

impl Addr {
    fn parse(connect: &str) -> Result<Self> {
        if let Some(path) = connect.strip_prefix("unix://") {
            Ok(Self::Unix {
                path: path.to_string(),
                base: "http://localhost".to_string(),
            })
        } else if let Some(host) = connect.strip_prefix("tcp://") {
            Ok(Self::Tcp {
                base: format!("http://{}", host),
            })
        } else if connect.starts_with('/') {
            // Bare path, treated as a Unix socket for convenience.
            Ok(Self::Unix {
                path: connect.to_string(),
                base: "http://localhost".to_string(),
            })
        } else {
            // Bare host:port, treated as TCP.
            Ok(Self::Tcp {
                base: format!("http://{}", connect),
            })
        }
    }

    fn url(&self, path: &str) -> String {
        match self {
            Addr::Unix { base, .. } | Addr::Tcp { base } => format!("{}{}", base, path),
        }
    }
}

// --- HTTP client ---

type HttpClient = Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>;

/// Build a request, connecting over the Unix socket directly when needed.
async fn connect_and_request(addr: &Addr, req: Request<Full<Bytes>>) -> Result<hyper::Response<hyper::body::Incoming>> {
    match addr {
        Addr::Tcp { .. } => {
            let client: HttpClient = Client::builder(TokioExecutor::new()).build_http();
            Ok(client.request(req).await?)
        }
        Addr::Unix { path, .. } => {
            let stream = tokio::net::UnixStream::connect(path)
                .await
                .context(format!("failed to connect Unix socket: {}", path))?;
            let io = hyper_util::rt::TokioIo::new(stream);
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    log::error!("Unix socket connection error: {}", e);
                }
            });
            Ok(sender.send_request(req).await?)
        }
    }
}

/// GET `path` and deserialize the JSON body.
async fn fetch_json<T: for<'de> Deserialize<'de>>(addr: &Addr, path: &str) -> Result<T> {
    let uri: Uri = addr.url(path).parse()?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))?;
    let resp = connect_and_request(addr, req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        anyhow::bail!("GET {} -> {}: {}", path, status, String::from_utf8_lossy(&body));
    }
    Ok(serde_json::from_slice(&body)?)
}

/// POST a JSON body to `path`, returning the deserialized response.
async fn post_json<B: serde::Serialize, T: for<'de> Deserialize<'de>>(
    addr: &Addr,
    path: &str,
    body: &B,
) -> Result<T> {
    let uri: Uri = addr.url(path).parse()?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(body)?)))?;
    let resp = connect_and_request(addr, req).await?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        anyhow::bail!("POST {} -> {}: {}", path, status, String::from_utf8_lossy(&bytes));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// DELETE `path`, returning the HTTP status.
async fn delete_path(addr: &Addr, path: &str) -> Result<StatusCode> {
    let uri: Uri = addr.url(path).parse()?;
    let req = Request::builder()
        .method(Method::DELETE)
        .uri(uri)
        .body(Full::new(Bytes::new()))?;
    let resp = connect_and_request(addr, req).await?;
    Ok(resp.status())
}

// --- Background data events ---

enum DataEvent {
    Stats(StatsResponse),
    Status(StatusResponse),
    Fingerprints(Vec<DpiFingerprint>),
    Alert(String),
    Disconnected,
}

// --- App state ---

/// Which panel currently holds keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Panel {
    Stats,
    TopFlows,
    Fingerprints,
    Alerts,
}

impl Panel {
    fn next(self) -> Self {
        match self {
            Panel::Stats => Panel::TopFlows,
            Panel::TopFlows => Panel::Fingerprints,
            Panel::Fingerprints => Panel::Alerts,
            Panel::Alerts => Panel::Stats,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Panel::Stats => "Stats",
            Panel::TopFlows => "Top Flows",
            Panel::Fingerprints => "Fingerprints",
            Panel::Alerts => "Alerts",
        }
    }
}

/// Modal mode: normal navigation, adding a fingerprint, or confirming a delete.
enum Mode {
    Normal,
    AddFingerprint { input: String },
    ConfirmDelete { id: Uuid, name: String },
}

struct App {
    stats: StatsResponse,
    status: StatusResponse,
    fingerprints: Vec<DpiFingerprint>,
    alerts: Vec<String>,
    focused: Panel,
    mode: Mode,
    flow_scroll: usize,
    fp_selected: usize,
    alert_scroll: usize,
    connected: bool,
    last_error: Option<String>,
    last_refresh: Instant,
    start: Instant,
    last_pps: f64,
    last_bps: f64,
    last_hit_total: u64,
}

impl App {
    fn new() -> Self {
        Self {
            stats: StatsResponse {
                total_packets: 0,
                total_bytes: 0,
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
                active_flows: 0,
                top_flows: Vec::new(),
            },
            status: StatusResponse {
                version: "?".into(),
                uptime_secs: 0,
                sampler_connected: false,
            },
            fingerprints: Vec::new(),
            alerts: Vec::new(),
            focused: Panel::Stats,
            mode: Mode::Normal,
            flow_scroll: 0,
            fp_selected: 0,
            alert_scroll: 0,
            connected: false,
            last_error: None,
            last_refresh: Instant::now(),
            start: Instant::now(),
            last_pps: 0.0,
            last_bps: 0.0,
            last_hit_total: 0,
        }
    }

    fn uptime(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    /// Total fingerprint hit count. The API does not yet expose per-rule hit
    /// counters, so this sums the number of active rules as a placeholder.
    fn hit_total(&self) -> u64 {
        self.fingerprints.len() as u64
    }
}

fn trend(current: f64, previous: f64) -> &'static str {
    if current > previous * 1.01 {
        "▲"
    } else if current < previous * 0.99 {
        "▼"
    } else {
        "─"
    }
}

// --- Main ---

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args = Args::parse();
    let addr = Addr::parse(&args.connect)?;
    let addr = std::sync::Arc::new(addr);
    println!("FlowFang TUI connecting to {}...", args.connect);

    // Initial connection check: retry until the analyzer answers.
    let mut app = App::new();
    loop {
        match fetch_json::<StatusResponse>(&addr, "/api/status").await {
            Ok(status) => {
                app.status = status;
                app.connected = true;
                break;
            }
            Err(e) => {
                eprintln!("Failed to connect to analyzer at {}: {}", args.connect, e);
                eprintln!("Retrying in 2s... (Ctrl-C to abort)");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
    }
    println!("Connected! FlowFang v{}", app.status.version);

    // Channel for background data events into the UI loop.
    let (tx, mut rx) = mpsc::unbounded_channel::<DataEvent>();

    // Spawn the SSE alert listener (reconnects internally on failure).
    spawn_alerts(addr.clone(), tx.clone());
    // Kick off the first poll cycle.
    spawn_poll(addr.clone(), tx.clone());

    // Setup terminal
    let mut stdout = io::stdout();
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_loop(&mut terminal, &mut app, &mut rx, &addr, &tx).await;

    // Cleanup terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;

    res
}

/// Spawn a poll cycle: stats+status every 1s, fingerprints every 5s.
/// Each cycle re-spawns the next one after gathering results, so polling
/// resumes automatically after a disconnect.
fn spawn_poll(addr: std::sync::Arc<Addr>, tx: mpsc::UnboundedSender<DataEvent>) {
    tokio::spawn(async move {
        let mut fp_tick = 0u32;
        loop {
            let mut ok = true;

            match fetch_json::<StatsResponse>(&addr, "/api/stats").await {
                Ok(s) => {
                    let _ = tx.send(DataEvent::Stats(s));
                }
                Err(_) => ok = false,
            }
            // Status rides along with the 1s stats poll.
            match fetch_json::<StatusResponse>(&addr, "/api/status").await {
                Ok(status) => {
                    let _ = tx.send(DataEvent::Status(status));
                }
                Err(_) => ok = false,
            }

            if fp_tick % 5 == 0 {
                match fetch_json::<Vec<DpiFingerprint>>(&addr, "/api/fingerprints").await {
                    Ok(fps) => {
                        let _ = tx.send(DataEvent::Fingerprints(fps));
                    }
                    Err(_) => ok = false,
                }
            }
            fp_tick = fp_tick.wrapping_add(1);

            if !ok {
                let _ = tx.send(DataEvent::Disconnected);
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Spawn the SSE listener for `/api/events`, reconnecting on failure.
fn spawn_alerts(addr: std::sync::Arc<Addr>, tx: mpsc::UnboundedSender<DataEvent>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = stream_events(&addr, &tx).await {
                log::warn!("SSE stream ended: {}", e);
            }
            // Back off, then reconnect.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn stream_events(addr: &Addr, tx: &mpsc::UnboundedSender<DataEvent>) -> Result<()> {
    let uri: Uri = addr.url("/api/events").parse()?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("accept", "text/event-stream")
        .body(Full::new(Bytes::new()))?;
    let resp = connect_and_request(addr, req).await?;
    if !resp.status().is_success() {
        anyhow::bail!("GET /api/events -> {}", resp.status());
    }
    let mut stream = resp.into_body().into_data_stream();
    let mut buf = String::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buf.push_str(&String::from_utf8_lossy(&chunk));
        // SSE frames are separated by blank lines.
        while let Some(pos) = buf.find("\n\n") {
            let frame = buf[..pos].to_string();
            buf.drain(..pos + 2);
            for line in frame.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    let data = data.trim();
                    if !data.is_empty() && data != "heartbeat" {
                        let _ = tx.send(DataEvent::Alert(data.to_string()));
                    }
                }
            }
        }
    }
    Ok(())
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: &mut mpsc::UnboundedReceiver<DataEvent>,
    addr: &std::sync::Arc<Addr>,
    _tx: &mpsc::UnboundedSender<DataEvent>,
) -> Result<()> {
    loop {
        // Drain pending data events.
        while let Ok(ev) = rx.try_recv() {
            match ev {
                DataEvent::Stats(s) => {
                    // Record the previous rates for the trend indicators,
                    // then install the fresh sample.
                    app.last_pps = app.stats.packets_per_second;
                    app.last_bps = app.stats.bytes_per_second;
                    app.stats = s;
                    app.connected = true;
                    app.last_error = None;
                    app.last_refresh = Instant::now();
                }
                DataEvent::Status(status) => {
                    app.status = status;
                }
                DataEvent::Fingerprints(fps) => {
                    app.last_hit_total = app.hit_total();
                    app.fingerprints = fps;
                    if app.fp_selected >= app.fingerprints.len() {
                        app.fp_selected = app.fingerprints.len().saturating_sub(1);
                    }
                }
                DataEvent::Alert(msg) => {
                    if !msg.is_empty() {
                        app.alerts.push(format!(
                            "[{}] {}",
                            chrono_lite_timestamp(),
                            msg
                        ));
                        // Cap the alert log.
                        if app.alerts.len() > 200 {
                            let excess = app.alerts.len() - 200;
                            app.alerts.drain(..excess);
                        }
                    }
                }
                DataEvent::Disconnected => {
                    app.connected = false;
                    app.last_error = Some("connection lost — retrying…".into());
                }
            }
        }

        terminal.draw(|f| ui(f, app))?;

        // Poll for input with a short timeout so the UI stays live.
        if crossterm::event::poll(Duration::from_millis(100))? {
            if let CtEvent::Key(key) = crossterm::event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                if handle_key(app, key, addr).await? {
                    return Ok(());
                }
            }
        }
    }
}

/// Handle one key press. Returns `true` to quit.
async fn handle_key(
    app: &mut App,
    key: KeyEvent,
    addr: &std::sync::Arc<Addr>,
) -> Result<bool> {
    match &mut app.mode {
        Mode::AddFingerprint { input } => match key.code {
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Enter => {
                let name = input.trim().to_string();
                app.mode = Mode::Normal;
                if !name.is_empty() {
                    let fp = DpiFingerprint {
                        id: Uuid::new_v4(),
                        name,
                        pattern: DpiPattern::ByteSeq { sequence: Vec::new() },
                        action: ProcessorAction::Pass,
                    };
                    match post_json::<_, DpiFingerprint>(addr, "/api/fingerprints", &fp).await {
                        Ok(_) => {
                            app.alerts
                                .push(format!("[{}] added fingerprint", chrono_lite_timestamp()));
                        }
                        Err(e) => {
                            app.alerts
                                .push(format!("[{}] add failed: {}", chrono_lite_timestamp(), e));
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Char(c) => {
                if !key.modifiers.contains(KeyModifiers::CONTROL) {
                    input.push(c);
                }
            }
            _ => {}
        },
        Mode::ConfirmDelete { id, .. } => {
            let id = *id;
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    app.mode = Mode::Normal;
                    match delete_path(addr, &format!("/api/fingerprints/{}", id)).await {
                        Ok(status) if status.is_success() => {
                            app.alerts.push(format!(
                                "[{}] deleted fingerprint",
                                chrono_lite_timestamp()
                            ));
                        }
                        Ok(status) => {
                            app.alerts.push(format!(
                                "[{}] delete failed: {}",
                                chrono_lite_timestamp(),
                                status
                            ));
                        }
                        Err(e) => {
                            app.alerts.push(format!(
                                "[{}] delete failed: {}",
                                chrono_lite_timestamp(),
                                e
                            ));
                        }
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    app.mode = Mode::Normal;
                }
                _ => {}
            }
        }
        Mode::Normal => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('s') => app.focused = Panel::Stats,
            KeyCode::Char('f') => app.focused = Panel::Fingerprints,
            KeyCode::Char('a') => {
                app.mode = Mode::AddFingerprint {
                    input: String::new(),
                }
            }
            KeyCode::Char('d') => {
                if app.focused == Panel::Fingerprints && !app.fingerprints.is_empty() {
                    let fp = &app.fingerprints[app.fp_selected.min(app.fingerprints.len() - 1)];
                    app.mode = Mode::ConfirmDelete {
                        id: fp.id,
                        name: fp.name.clone(),
                    };
                }
            }
            KeyCode::Tab => app.focused = app.focused.next(),
            KeyCode::Up => match app.focused {
                Panel::TopFlows => app.flow_scroll = app.flow_scroll.saturating_sub(1),
                Panel::Fingerprints => app.fp_selected = app.fp_selected.saturating_sub(1),
                Panel::Alerts => app.alert_scroll = app.alert_scroll.saturating_sub(1),
                Panel::Stats => {}
            },
            KeyCode::Down => match app.focused {
                Panel::TopFlows => app.flow_scroll += 1,
                Panel::Fingerprints => {
                    if app.fp_selected + 1 < app.fingerprints.len() {
                        app.fp_selected += 1;
                    }
                }
                Panel::Alerts => app.alert_scroll += 1,
                Panel::Stats => {}
            },
            _ => {}
        },
    }
    Ok(false)
}

/// Minimal local timestamp (HH:MM:SS) without pulling in a clock crate.
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// --- UI Drawing ---

fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    draw_header(f, chunks[0], app);

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(chunks[1]);

    draw_stats(f, main[0], app);

    let lower = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main[1]);

    draw_flows(f, lower[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(lower[1]);

    draw_fingerprints(f, right[0], app);
    draw_alerts(f, right[1], app);

    draw_footer(f, chunks[2], app);

    // Modal overlays
    match &app.mode {
        Mode::AddFingerprint { input } => draw_add_modal(f, input),
        Mode::ConfirmDelete { name, .. } => draw_delete_modal(f, name),
        Mode::Normal => {}
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let conn = if app.connected { "🟢 up" } else { "🔴 down" };
    let mut spans = vec![
        Span::styled(
            "FlowFang",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" v{}  |  ", app.status.version)),
        Span::raw(format!("Analyzer: {}  |  ", conn)),
        Span::raw(format!(
            "Sampler: {}  |  ",
            if app.status.sampler_connected { "🟢" } else { "🔴" }
        )),
        Span::raw(format!("Uptime: {}s", app.uptime())),
    ];
    if let Some(err) = &app.last_error {
        spans.push(Span::raw("  |  "));
        spans.push(Span::styled(err.clone(), Style::default().fg(Color::Red)));
    }
    let header = Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL));
    f.render_widget(header, area);
}

fn draw_stats(f: &mut Frame, area: Rect, app: &App) {
    let stat_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 4); 4])
        .split(area);

    let hit_total = app.hit_total();
    let stats = [
        (
            "PPS",
            format!("{:.0} {}", app.stats.packets_per_second, trend(app.stats.packets_per_second, app.last_pps)),
        ),
        (
            "BPS",
            format!("{} {}", format_bytes(app.stats.bytes_per_second as u64), trend(app.stats.bytes_per_second, app.last_bps)),
        ),
        ("Active Flows", format!("{}", app.stats.active_flows)),
        (
            "FP Hits",
            format!("{} {}", hit_total, trend(hit_total as f64, app.last_hit_total as f64)),
        ),
    ];

    let focused = app.focused == Panel::Stats;
    for (i, (label, value)) in stats.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style(focused))
            .title(Span::styled(*label, Style::default().fg(Color::Yellow)));
        let text = Paragraph::new(Text::from(Line::from(Span::styled(
            value.as_str(),
            Style::default().add_modifier(Modifier::BOLD),
        ))))
        .block(block)
        .alignment(Alignment::Center);
        f.render_widget(text, stat_chunks[i]);
    }
}

fn draw_flows(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["Src IP", "Dst IP", "SPort", "DPort", "Proto", "pps", "Bytes"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .stats
        .top_flows
        .iter()
        .skip(app.flow_scroll)
        .take(10)
        .map(|flow| {
            Row::new(vec![
                flow.src_ip.clone(),
                flow.dst_ip.clone(),
                flow.src_port.to_string(),
                flow.dst_port.to_string(),
                proto_name(flow.protocol),
                // Per-flow pps is approximated from packets; the API reports
                // cumulative packet counts per flow.
                flow.packets.to_string(),
                format_bytes(flow.bytes),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
            Constraint::Ratio(1, 7),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style(app.focused == Panel::TopFlows))
            .title("Top Flows"),
    )
    .column_spacing(1);

    f.render_widget(table, area);
}

fn draw_fingerprints(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused == Panel::Fingerprints;
    let items: Vec<ListItem> = app
        .fingerprints
        .iter()
        .map(|fp| {
            ListItem::new(Line::from(vec![
                Span::styled(fp.name.clone(), Style::default().fg(Color::White)),
                Span::raw(format!("  [{}]", pattern_name(&fp.pattern))),
                Span::raw(format!("  -> {}", action_name(&fp.action))),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style(focused))
                .title(format!("Fingerprints ({})", app.fingerprints.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("» ");

    let mut state = ListState::default();
    if !app.fingerprints.is_empty() {
        state.select(Some(app.fp_selected.min(app.fingerprints.len() - 1)));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_alerts(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focused == Panel::Alerts;
    let items: Vec<ListItem> = app
        .alerts
        .iter()
        .rev()
        .skip(app.alert_scroll)
        .map(|a| ListItem::new(a.clone()))
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style(focused))
            .title("Alerts"),
    );
    f.render_widget(list, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = match &app.mode {
        Mode::Normal => {
            " q: quit  Tab: next panel  s: stats  f: fingerprints  a: add fp  d: del fp  ↑↓: scroll "
        }
        Mode::AddFingerprint { .. } => " Enter: add  Esc: cancel ",
        Mode::ConfirmDelete { .. } => " y/Enter: confirm delete  n/Esc: cancel ",
    };
    let focused = format!(" [{}] ", app.focused.title());
    let footer = Paragraph::new(Line::from(vec![
        Span::raw(hint),
        Span::styled(focused, Style::default().bg(Color::DarkGray)),
    ]));
    f.render_widget(footer, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn draw_add_modal(f: &mut Frame, input: &str) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Add Fingerprint")
        .border_style(Style::default().fg(Color::Cyan));
    let para = Paragraph::new(Line::from(vec![
        Span::raw("Name: "),
        Span::styled(input, Style::default().fg(Color::Yellow)),
        Span::styled("█", Style::default().fg(Color::Gray)),
    ]))
    .block(block)
    .wrap(Wrap { trim: true });
    f.render_widget(para, area);
}

fn draw_delete_modal(f: &mut Frame, name: &str) {
    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Delete Fingerprint")
        .border_style(Style::default().fg(Color::Red));
    let para = Paragraph::new(vec![
        Line::from(format!("Delete \"{}\"?", name)),
        Line::from(""),
        Line::from(Span::styled(
            "y/Enter to confirm, n/Esc to cancel",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(block)
    .wrap(Wrap { trim: true });
    f.render_widget(para, area);
}

fn proto_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        _ => format!("{}", proto),
    }
}

fn pattern_name(pattern: &DpiPattern) -> &'static str {
    match pattern {
        DpiPattern::ExactMatch { .. } => "exact",
        DpiPattern::ByteSeq { .. } => "byteseq",
        DpiPattern::Regex { .. } => "regex",
        DpiPattern::TlsSni { .. } => "tls-sni",
        DpiPattern::TlsJa3 { .. } => "tls-ja3",
    }
}

fn action_name(action: &ProcessorAction) -> String {
    match action {
        ProcessorAction::Pass => "pass".into(),
        ProcessorAction::Drop => "drop".into(),
        ProcessorAction::Mark { mark } => format!("mark:{}", mark),
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}
