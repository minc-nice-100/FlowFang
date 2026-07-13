//! FlowFang TUI — terminal dashboard for the FlowFang traffic audit system.
//!
//! Connects to the analyzer's HTTP API to display real-time traffic
//! statistics, active fingerprint rules, and alerts.

use anyhow::Result;
use clap::Parser;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame,
};
use std::io;

/// FlowFang TUI — terminal audit dashboard.
#[derive(Parser)]
#[command(name = "flow-analyzer-tui", version)]
struct Args {
    /// Analyzer API address (unix socket or TCP)
    #[arg(short, long, default_value = "unix:///var/run/flowfang.sock")]
    connect: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("FlowFang TUI connecting to {}...", args.connect);
    println!("(TUI implementation pending — run `cargo test` first)");
    Ok(())
}