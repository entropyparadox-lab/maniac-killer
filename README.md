# 🩸 Maniac Killer (`maniac-killer`)

[![Crates.io](https://img.shields.io/crates/v/maniac-killer.svg)](https://crates.io/crates/maniac-killer)
[![CI](https://github.com/cycorld/maniac-killer/actions/workflows/ci.yml/badge.svg)](https://github.com/cycorld/maniac-killer/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

> **The AI-Agent-Aware Process Watchdog & Remote Executioner for macOS & Linux.**  
> Real-time runaway process detection, instant Slack/Discord/Telegram ChatOps, and **100% immune guarantee for your active Claude Code & AI agent sessions**.

```
  ███╗   ███╗ █████╗ ███╗   ██╗██╗ █████╗  ██████╗
  ████╗ ████║██╔══██╗████╗  ██║██║██╔══██╗██╔════╝
  ██╔████╔██║███████║██╔██╗ ██║██║███████║██║     
  ██║╚██╔╝██║██╔══██║██║╚██╗██║██║██╔══██║██║     
  ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║██║  ██║╚██████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝ ╚═════╝
          ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
          ██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
          █████╔╝ ██║██║     ██║     █████╗  ██████╔╝
          ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
          ██║  ██╗██║███████╗███████╗███████╗██║  ██║
          ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
```

---

## 🎯 The Problem

In the modern **AI coding and autonomous agent era**, developers frequently run long-lived AI CLI tools like **Claude Code, Codex, Aider, and Hermes**. 

These agents frequently spin up sub-processes:
- 🌀 **Next.js & Webpack HMR servers** that get trapped in 300% CPU busy loops
- 👻 **Orphaned headless browsers** (`agent-browser`, Playwright, Puppeteer) with `PPID 1` hoarding gigabytes of memory and swap
- 🔄 **Stuck test runners** (`bun test`, `vitest`) spinning endlessly in the background
- 💥 **Crashing MCP servers** stuck in rapid restart loops

Traditional process managers or blind auto-killers either:
1. Require you to constantly open SSH and run `top`/`kill`, OR
2. **Accidentally kill your active Claude Code / AI terminal sessions** along with the bad processes!

---

## ✨ Features

- 🛡️ **Zero-False-Positive AI Agent Immunity**: Built-in system-level immunity rules protect Claude Code, coding CLIs, tmux sessions, and critical OS daemons from accidental termination.
- 🩸 **Interactive ChatOps (Slack / Discord / Telegram)**: Receive rich alert cards with process metadata, CPU%, memory RSS, and working directory, along with one-click **`[🩸 KILL NOW]`**, **`[🛡️ Whitelist]`**, and **`[⏳ Mute]`** buttons.
- ⚡ **Lightweight & Blazing Fast**: Single 5MB native Rust binary. Consumes **0.0% CPU** and **<10MB RAM** while idling.
- 🌐 **Web Control Center**: Built-in dark-themed web dashboard for inspecting live tracked runaways and executing manual kills over Tailscale or LAN.
- 🔌 **Graceful Two-Stage Termination**: First attempts safe `SIGTERM` (1.2s grace period). Escalates to `SIGKILL` only if the process is unresponsive.

---

## 🚀 Quick Start

### Installation

#### Cargo
```bash
cargo install maniac-killer
```

#### Pre-built Binaries (GitHub Releases)
```bash
# macOS Apple Silicon
curl -fsSL https://github.com/cycorld/maniac-killer/releases/latest/download/maniac-killer-aarch64-apple-darwin.tar.gz | tar -xz && sudo mv maniac-killer /usr/local/bin/

# Linux x86_64
curl -fsSL https://github.com/cycorld/maniac-killer/releases/latest/download/maniac-killer-x86_64-unknown-linux-gnu.tar.gz | tar -xz && sudo mv maniac-killer /usr/local/bin/
```

---

## ⚙️ Configuration

Generate a starter configuration file:
```bash
maniac-killer init
```

Edit `maniac-killer.toml` (or `~/.config/maniac-killer/config.toml`):

```toml
# Sampling interval in seconds
check_interval_secs = 10

# CPU percentage to classify as runaway (e.g. 120%)
cpu_threshold = 120.0

# Number of consecutive checks required before alerting
cpu_streak = 3

# Memory threshold in MB
mem_threshold_mb = 4096

# Webhook dashboard port
http_port = 19999
http_host = "0.0.0.0"

# Public/Tailscale base URL for Slack/Discord clickable buttons
base_url = "http://your-host.ts.net:19999"

# Notification Channels (Configure any or all)
slack_bot_token = "xoxb-your-token"
slack_channel = "C0B552ZK220" # e.g. #log-claude-status

discord_webhook_url = "https://discord.com/api/webhooks/..."

telegram_bot_token = "123456:ABC-DEF..."
telegram_chat_id = "-100123456789"

# Custom whitelist keywords
custom_whitelist = [
    "my-heavy-batch-job",
    "custom-local-model"
]
```

---

## 📖 CLI Usage

```bash
# 1. Start live watchdog daemon and web dashboard
maniac-killer watch

# 2. Run a one-shot deep scan
maniac-killer scan

# 3. Safely kill a PID with immunity check
maniac-killer kill <PID>

# 4. Check current suspects via running daemon
maniac-killer status
```

---

## 🛡️ Immunity & Safety Rules

Maniac Killer includes strict, hardcoded immunity checks before any signal is dispatched:

1. **AI Agent Sessions**: Any process matching `claude`, `claude --`, `codex`, `cursor`, `aider`, `hermes`, `opencode` is strictly immune.
2. **System Daemons**: `launchd`, `systemd`, `WindowServer`, `sshd`, `fseventsd`, `kernel_task`, `loginwindow` are protected.
3. **Databases & Virtualization**: `postgres`, `mysqld`, `redis-server`, `docker`, `orbstack`, `tailscaled` are protected.
4. **PID Guard**: PIDs $\le 100$ are unconditionally protected.

---

## 🏃 Running as a Service

### PM2
```bash
pm2 start maniac-killer --name "maniac-killer" -- watch
pm2 save
```

### systemd (Linux)
```ini
[Unit]
Description=Maniac Killer Runaway Process Watchdog
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/maniac-killer watch
Restart=always
RestartSec=5
User=youruser

[Install]
WantedBy=multi-user.target
```

---

## 📜 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
