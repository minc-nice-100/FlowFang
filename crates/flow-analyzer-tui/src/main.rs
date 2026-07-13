//! FlowFang TUI — terminal dashboard for the FlowFang traffic audit system.
//!
//! Connects to the analyzer's HTTP API to display real-time traffic
//! statistics, active fingerprint rules, and alerts.

use anyhow::{Context, Result};
use clap::Parser;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame, Terminal,
};
use reqwest::Client;
use serde::Deserialize;
use std::io;
use std::time::Duration;

/// FlowFang TUI — terminal audit dashboard.
#[derive(Parser)]
#[command(name = "flow-analyzer-tui", version)]
struct Args {
    /// Analyzer API address (unix socket path or TCP host:port)
    #[arg(short, long, default_value = "/var/run/flowfang.sock")]
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

#[derive(Deserialize, Debug)]
struct FlowInfo {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    packets: u64,
    bytes: u64,
}

#[derive(Deserialize, Debug)]
struct FingerprintInfo {
    id: String,
    name: String,
    // pattern and action are displayed as strings from the API
}

// --- App state ---

struct App {
    stats: StatsResponse,
    status: StatusResponse,
    selected_tab: usize,
    scroll_offset: usize,
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
            selected_tab: 0,
            scroll_offset: 0,
        }
    }
}

// --- HTTP client ---

fn build_client(connect: &str) -> Result<Client> {
    if connect.starts_with('/') || connect.contains('/') {
        // Unix socket
        let socket_path = connect.to_string();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        // reqwest Unix socket requires a separate connector setup;
        // for simplicity, assume TCP for now.
        // In production, use hyperlocal or similar.
        Ok(client)
    } else {
        Ok(Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?)
    }
}

async fn fetch_stats(client: &Client, connect: &str) -> Result<StatsResponse> {
    let url = if connect.starts_with('/') {
        format!("http://localhost/api/stats")
    } else {
        format!("http://{}/api/stats", connect)
    };
    let resp = client.get(&url).send().await?;
    let stats = resp.json().await?;
    Ok(stats)
}

async fn fetch_status(client: &Client, connect: &str) -> Result<StatusResponse> {
    let url = if connect.starts_with('/') {
        format!("http://localhost/api/status")
    } else {
        format!("http://{}/api/status", connect)
    };
    let resp = client.get(&url).send().await?;
    let status = resp.json().await?;
    Ok(status)
}

// --- Main ---

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    println!("FlowFang TUI connecting to {}...", args.connect);

    let client = build_client(&args.connect)?;
    let mut app = App::new();

    // Check connection
    match fetch_status(&client, &args.connect).await {
        Ok(status) => {
            app.status = status;
            println!("Connected! FlowFang v{}", app.status.version);
        }
        Err(e) => {
            anyhow::bail!("Failed to connect to analyzer: {}", e);
        }
    }

    // Setup terminal
    let mut stdout = io::stdout();
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let tick_rate = Duration::from_secs(1);
    let mut last_tick = tokio::time::Instant::now();

    loop {
        // Fetch stats every tick
        if last_tick.elapsed() >= tick_rate {
            last_tick = tokio::time::Instant::now();
            if let Ok(stats) = fetch_stats(&client, &args.connect).await {
                app.stats = stats;
            }
            if let Ok(status) = fetch_status(&client, &args.connect).await {
                app.status = status;
            }
        }

        // Draw UI
        terminal.draw(|f| ui(f, &app))?;

        // Handle input
        if crossterm::event::poll(Duration::from_millis(100))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                match key.code {
                    crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Esc => {
                        break;
                    }
                    crossterm::event::KeyCode::Char('f') => app.selected_tab = 1,
                    crossterm::event::KeyCode::Char('s') => app.selected_tab = 0,
                    crossterm::event::KeyCode::Up => {
                        app.scroll_offset = app.scroll_offset.saturating_sub(1);
                    }
                    crossterm::event::KeyCode::Down => {
                        app.scroll_offset += 1;
                    }
                    crossterm::event::KeyCode::Tab => {
                        app.selected_tab = (app.selected_tab + 1) % 2;
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup terminal
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;

    Ok(())
}

// --- UI Drawing ---

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

    // Header
    let header = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("FlowFang", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" v{}  |  ", app.status.version)),
            Span::raw(format!(
                "Sampler: {}  |  ",
                if app.status.sampler_connected { "🟢" } else { "🔴" }
            )),
            Span::raw(format!("Uptime: {}s", app.status.uptime_secs)),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL))
    .style(Style::default());
    f.render_widget(header, chunks[0]);

    // Main content
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(0),
        ])
        .split(chunks[1]);

    // Stats row
    draw_stats(f, main_chunks[0], app);

    // Top flows table
    draw_flows(f, main_chunks[1], app);

    // Footer
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" q: quit ", Style::default().bg(Color::DarkGray)),
        Span::styled(" s: stats ", Style::default().bg(Color::DarkGray)),
        Span::styled(" f: flows ", Style::default().bg(Color::DarkGray)),
        Span::styled(" ↑↓: scroll ", Style::default().bg(Color::DarkGray)),
        Span::styled(" Tab: switch ", Style::default().bg(Color::DarkGray)),
    ]))
    .style(Style::default());
    f.render_widget(footer, chunks[2]);
}

fn draw_stats(f: &mut Frame, area: Rect, app: &App) {
    let stat_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(area);

    let stats = [
        ("Packets", format!("{}", app.stats.total_packets)),
        ("Bytes", format_bytes(app.stats.total_bytes)),
        ("PPS", format!("{:.0}", app.stats.packets_per_second)),
        ("Flows", format!("{}", app.stats.active_flows)),
    ];

    for (i, (label, value)) in stats.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(*label, Style::default().fg(Color::Yellow)));
        let text = Paragraph::new(Text::from(vec![
            Line::from(Span::styled(
                value.as_str(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ]))
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, stat_chunks[i]);
    }
}

fn draw_flows(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(vec!["Src IP", "Dst IP", "Sport", "Dport", "Proto", "Packets", "Bytes"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .stats
        .top_flows
        .iter()
        .skip(app.scroll_offset)
        .map(|flow| {
            Row::new(vec![
                flow.src_ip.clone(),
                flow.dst_ip.clone(),
                flow.src_port.to_string(),
                flow.dst_port.to_string(),
                proto_name(flow.protocol),
                flow.packets.to_string(),
                format_bytes(flow.bytes),
            ])
        })
        .collect();

    let table = Table::new(rows, [
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
        Constraint::Ratio(1, 7),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Top Flows"))
    .column_spacing(1);

    f.render_widget(table, area);
}

fn proto_name(proto: u8) -> String {
    match proto {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        _ => format!("{}", proto),
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