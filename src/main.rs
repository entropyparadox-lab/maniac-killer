mod auth;
mod config;
mod detector;
mod killer;
mod notifier;
mod protection;
mod server;

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use config::Config;
use detector::Detector;
use killer::Executioner;
use notifier::Notifier;
use server::{create_router, AppState};

#[derive(Parser)]
#[command(name = "maniac-killer")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Custom configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the background watchdog daemon and interactive Webhook server
    Watch {
        /// Sampling interval in seconds (default: 10s)
        #[arg(short, long)]
        interval: Option<u64>,

        /// CPU threshold percentage (default: 120%)
        #[arg(short, long)]
        cpu_threshold: Option<f32>,

        /// Webhook server listening port (default: 19999)
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Run a one-shot deep scan for runaway/orphaned processes
    Scan,

    /// Safely terminate a specific process after double-checking agent immunity
    Kill {
        /// Target Process ID
        pid: u32,
    },

    /// Query and display currently tracked runaway processes from the live daemon
    Status,

    /// Generate a fresh template configuration file (`maniac-killer.toml`)
    Init {
        #[arg(short, long, default_value = "maniac-killer.toml")]
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();
    let mut config = Config::load_or_default(cli.config.as_deref());

    match cli.command.unwrap_or(Commands::Watch {
        interval: None,
        cpu_threshold: None,
        port: None,
    }) {
        Commands::Init { path } => {
            let toml_str = toml::to_string_pretty(&config).unwrap();
            std::fs::write(&path, toml_str).expect("Failed to write config file");
            println!("✨ Initialized template configuration file at: {:?}", path);
        }
        Commands::Scan => {
            let server_name = config.get_server_name();
            println!(
                "🔍 [MANIAC KILLER] Scanning for runaway & orphaned processes on {}...",
                server_name
            );
            let mut detector = Detector::new(config.custom_whitelist.clone());
            let suspects = detector.scan(&config);

            if suspects.is_empty() {
                println!(
                    "✨ [{}] No runaway processes found exceeding CPU {:.0}% or orphan criteria.",
                    server_name, config.cpu_threshold
                );
            } else {
                println!(
                    "🚨 [{}] Discovered {} suspect/runaway process(es):",
                    server_name,
                    suspects.len()
                );
                for p in suspects {
                    println!(
                        "  • [PID {}] {} | CPU: {:.1}% | MEM: {}MB | Reason: {}\n    CWD: {}\n    CMD: {}",
                        p.pid, p.name, p.cpu_percent, p.memory_mb, p.reason, p.cwd, p.cmdline
                    );
                }
            }
        }
        Commands::Kill { pid } => {
            println!(
                "⚔️ Target PID {} — validating agent immunity & executing...",
                pid
            );
            match Executioner::execute(pid, None, &config.custom_whitelist).await {
                Ok(result) => {
                    println!("🩸 Execution Result: {}", result.message);
                }
                Err(e) => {
                    eprintln!("⛔ Execution Failed: {}", e);
                }
            }
        }
        Commands::Status => {
            let addr = format!("http://127.0.0.1:{}/api/status", config.http_port);
            match reqwest::get(&addr).await {
                Ok(resp) => {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    }
                }
                Err(_) => {
                    println!(
                        "⚠️ maniac-killer daemon is not running on port {}.",
                        config.http_port
                    );
                }
            }
        }
        Commands::Watch {
            interval,
            cpu_threshold,
            port,
        } => {
            if let Some(i) = interval {
                config.check_interval_secs = i;
            }
            if let Some(c) = cpu_threshold {
                config.cpu_threshold = c;
            }
            if let Some(p) = port {
                config.http_port = p;
            }

            let server_name = config.get_server_name();
            let base_url = config.get_base_url();

            info!("🩸 MANIAC KILLER Watchdog starting on {}...", server_name);
            info!("  • Server Name: {}", server_name);
            info!("  • Sampling Interval: {}s", config.check_interval_secs);
            info!(
                "  • CPU Threshold: {:.0}% (Streak: {} checks)",
                config.cpu_threshold, config.cpu_streak
            );
            info!("  • Webhook Base URL: {}", base_url);
            if let Some(chan) = &config.slack_channel {
                info!("  • Slack Channel: {}", chan);
            }
            if config.discord_webhook_url.is_some() {
                info!("  • Discord Webhook: Enabled");
            }
            if config.telegram_chat_id.is_some() {
                info!("  • Telegram Chat: Enabled");
            }

            let detector = Arc::new(Mutex::new(Detector::new(config.custom_whitelist.clone())));
            let state = AppState {
                config: config.clone(),
                detector: Arc::clone(&detector),
            };

            // Start HTTP Action Server
            let app = create_router(state);
            let http_addr: SocketAddr = format!("{}:{}", config.http_host, config.http_port)
                .parse()
                .expect("Invalid bind address");

            tokio::spawn(async move {
                info!(
                    "🌐 Control Center Webhook listening on http://{}",
                    http_addr
                );
                match tokio::net::TcpListener::bind(http_addr).await {
                    Ok(listener) => {
                        if let Err(e) = axum::serve(listener, app).await {
                            error!("HTTP server error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to bind port {}: {}", http_addr, e);
                    }
                }
            });

            // Watchdog Loop
            let check_dur = Duration::from_secs(config.check_interval_secs);

            #[cfg(unix)]
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");

            info!("🚀 Watchdog loop running. Waiting for events or termination signals...");

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("🛑 Received SIGINT (Ctrl+C). Terminating MANIAC KILLER cleanly.");
                        break;
                    }
                    _ = async {
                        #[cfg(unix)]
                        {
                            sigterm.recv().await
                        }
                        #[cfg(not(unix))]
                        {
                            std::future::pending::<()>().await
                        }
                    } => {
                        info!("🛑 Received SIGTERM. Terminating MANIAC KILLER cleanly.");
                        break;
                    }
                    _ = tokio::time::sleep(check_dur) => {
                        let suspects = {
                            let mut det = detector.lock().await;
                            det.scan(&config)
                        };

                        for suspect in suspects {
                            warn!(
                                "🚨 [{}] RUNAWAY PROCESS DETECTED: [PID {}] {} (CPU {:.1}%, MEM {}MB) - {}",
                                server_name,
                                suspect.pid,
                                suspect.name,
                                suspect.cpu_percent,
                                suspect.memory_mb,
                                suspect.reason
                            );

                            // Dispatch alert to Slack / Discord / Telegram
                            Notifier::dispatch_alert(&config, &suspect, &base_url).await;
                        }
                    }
                }
            }
        }
    }
}
