use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server/Node identifier (e.g. "prod-app-01", "worker-node-2")
    pub server_name: Option<String>,

    /// SSH host alias for CLI kill hints in alert notifications (e.g. "server1", "worker-01")
    pub ssh_host: Option<String>,

    /// Watchdog sampling interval in seconds (default: 10)
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// CPU usage percentage threshold for runaway processes (default: 120.0%)
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: f32,

    /// Consecutive sampling streak required before triggering alert (default: 30 checks = 5 mins)
    #[serde(default = "default_cpu_streak")]
    pub cpu_streak: u32,

    /// Memory usage threshold in megabytes (default: 8192MB)
    #[serde(default = "default_mem_threshold_mb")]
    pub mem_threshold_mb: u64,

    /// Alert cooldown in minutes for the same runaway process (default: 120 mins = 2 hours)
    #[serde(default = "default_alert_cooldown_mins")]
    pub alert_cooldown_mins: i64,

    /// Webhook server listening port (default: 19999)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Webhook server bind host (default: "0.0.0.0")
    #[serde(default = "default_http_host")]
    pub http_host: String,

    /// Secret authentication token for action links (kill/mute/whitelist)
    #[serde(default = "default_auth_token")]
    pub auth_token: String,

    /// Public/Tailscale/LAN base URL for interactive buttons (e.g. "http://192.168.1.50:19999" or "https://monitor.internal:19999")
    pub base_url: Option<String>,

    /// Slack Bot OAuth Token (xoxb-...)
    pub slack_bot_token: Option<String>,

    /// Slack Alert Channel ID or Name (e.g. "C0B552ZK220" or "#log-claude-status")
    pub slack_channel: Option<String>,

    /// Discord Webhook URL for alerts
    pub discord_webhook_url: Option<String>,

    /// Telegram Bot Token
    pub telegram_bot_token: Option<String>,

    /// Telegram Chat ID
    pub telegram_chat_id: Option<String>,

    /// Telegram Thread / Topic ID (for forum supergroups)
    pub telegram_thread_id: Option<i64>,

    /// Alias for telegram_thread_id
    pub telegram_topic_id: Option<i64>,

    /// Custom process name/command keywords to immune from termination
    #[serde(default)]
    pub custom_whitelist: Vec<String>,
}

fn default_check_interval_secs() -> u64 {
    10
}
fn default_cpu_threshold() -> f32 {
    250.0
}
fn default_cpu_streak() -> u32 {
    30
}
fn default_mem_threshold_mb() -> u64 {
    8192
}
fn default_alert_cooldown_mins() -> i64 {
    120
}
fn default_http_port() -> u16 {
    19999
}
fn default_http_host() -> String {
    "0.0.0.0".to_string()
}
fn default_auth_token() -> String {
    use rand::Rng;
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    format!("maniac-{}", token)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_name: None,
            ssh_host: None,
            check_interval_secs: default_check_interval_secs(),
            cpu_threshold: default_cpu_threshold(),
            cpu_streak: default_cpu_streak(),
            mem_threshold_mb: default_mem_threshold_mb(),
            alert_cooldown_mins: default_alert_cooldown_mins(),
            http_port: default_http_port(),
            http_host: default_http_host(),
            auth_token: default_auth_token(),
            base_url: None,
            slack_bot_token: None,
            slack_channel: None,
            discord_webhook_url: None,
            telegram_bot_token: None,
            telegram_chat_id: None,
            telegram_thread_id: None,
            telegram_topic_id: None,
            custom_whitelist: Vec::new(),
        }
    }
}

impl Config {
    pub fn get_server_name(&self) -> String {
        if let Some(name) = &self.server_name {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }

        sysinfo::System::host_name().unwrap_or_else(|| {
            std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "unknown-server".to_string())
        })
    }

    pub fn get_ssh_host(&self) -> String {
        if let Some(host) = &self.ssh_host {
            if !host.trim().is_empty() {
                return host.trim().to_string();
            }
        }
        self.get_server_name()
    }

    pub fn get_base_url(&self) -> String {
        if let Some(url) = &self.base_url {
            if !url.trim().is_empty() {
                return url.trim().trim_end_matches('/').to_string();
            }
        }

        format!("http://localhost:{}", self.http_port)
    }

    pub fn load_or_default(custom_path: Option<&Path>) -> Self {
        let mut config = Self::default();

        let possible_paths = match custom_path {
            Some(p) => vec![p.to_path_buf()],
            None => vec![
                PathBuf::from("maniac-killer.toml"),
                dirs_home().join(".config/maniac-killer/config.toml"),
                dirs_home().join("Documents/maniac-killer/maniac-killer.toml"),
                PathBuf::from("/etc/maniac-killer/config.toml"),
            ],
        };

        for path in &possible_paths {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(parsed) = toml::from_str::<Config>(&content) {
                        config = parsed;
                        break;
                    }
                }
            }
        }

        // Environment Variable Overrides
        if let Ok(val) = std::env::var("MANIAC_SERVER_NAME") {
            config.server_name = Some(val);
        }
        if let Ok(val) = std::env::var("MANIAC_SSH_HOST") {
            config.ssh_host = Some(val);
        }
        if let Ok(val) = std::env::var("MANIAC_CHECK_INTERVAL") {
            if let Ok(parsed) = val.parse::<u64>() {
                config.check_interval_secs = parsed;
            }
        }
        if let Ok(val) = std::env::var("MANIAC_CPU_THRESHOLD") {
            if let Ok(parsed) = val.parse::<f32>() {
                config.cpu_threshold = parsed;
            }
        }
        if let Ok(val) = std::env::var("MANIAC_CPU_STREAK") {
            if let Ok(parsed) = val.parse::<u32>() {
                config.cpu_streak = parsed;
            }
        }
        if let Ok(val) = std::env::var("MANIAC_MEM_THRESHOLD_MB") {
            if let Ok(parsed) = val.parse::<u64>() {
                config.mem_threshold_mb = parsed;
            }
        }
        if let Ok(val) = std::env::var("MANIAC_HTTP_PORT") {
            if let Ok(parsed) = val.parse::<u16>() {
                config.http_port = parsed;
            }
        }
        if let Ok(val) = std::env::var("MANIAC_HTTP_HOST") {
            config.http_host = val;
        }
        if let Ok(val) = std::env::var("MANIAC_AUTH_TOKEN") {
            config.auth_token = val;
        }
        if let Ok(val) = std::env::var("MANIAC_BASE_URL") {
            config.base_url = Some(val);
        }

        // Auto-discover Slack tokens from environment or ~/.config/maniac-killer/maniac-killer.env
        if config.slack_bot_token.is_none() {
            if let Ok(tok) = std::env::var("MANIAC_SLACK_BOT_TOKEN")
                .or_else(|_| std::env::var("SLACK_BOT_TOKEN"))
            {
                config.slack_bot_token = Some(tok);
            } else {
                let conf_env = dirs_home().join(".config/maniac-killer/maniac-killer.env");
                if let Some((tok, chan)) = parse_env_file(&conf_env) {
                    config.slack_bot_token = Some(tok);
                    if config.slack_channel.is_none() {
                        config.slack_channel = Some(chan);
                    }
                }
            }
        }
        if config.slack_channel.is_none() {
            if let Ok(chan) = std::env::var("MANIAC_SLACK_CHANNEL")
                .or_else(|_| std::env::var("SLACK_ALERT_CHANNEL"))
            {
                config.slack_channel = Some(chan);
            }
        }

        // Discord
        if config.discord_webhook_url.is_none() {
            if let Ok(url) = std::env::var("MANIAC_DISCORD_WEBHOOK_URL")
                .or_else(|_| std::env::var("DISCORD_WEBHOOK_URL"))
            {
                config.discord_webhook_url = Some(url);
            }
        }

        // Telegram
        if config.telegram_bot_token.is_none() {
            if let Ok(tok) = std::env::var("MANIAC_TELEGRAM_BOT_TOKEN")
                .or_else(|_| std::env::var("TELEGRAM_BOT_TOKEN"))
            {
                config.telegram_bot_token = Some(tok);
            }
        }
        if config.telegram_chat_id.is_none() {
            if let Ok(cid) = std::env::var("MANIAC_TELEGRAM_CHAT_ID")
                .or_else(|_| std::env::var("TELEGRAM_CHAT_ID"))
            {
                config.telegram_chat_id = Some(cid);
            }
        }
        if config.telegram_thread_id.is_none() && config.telegram_topic_id.is_none() {
            if let Ok(tid) = std::env::var("MANIAC_TELEGRAM_THREAD_ID")
                .or_else(|_| std::env::var("TELEGRAM_THREAD_ID"))
                .or_else(|_| std::env::var("TELEGRAM_TOPIC_ID"))
            {
                if let Ok(num) = tid.parse::<i64>() {
                    config.telegram_thread_id = Some(num);
                }
            }
        }

        config
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn parse_env_file(path: &Path) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut token = None;
    let mut channel = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("SLACK_BOT_TOKEN=") {
            let clean = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            token = Some(clean);
        } else if let Some(val) = line.strip_prefix("SLACK_ALERT_CHANNEL=") {
            let clean = val.trim_matches(|c| c == '"' || c == '\'').to_string();
            channel = Some(clean);
        }
    }
    if let (Some(t), Some(c)) = (token, channel) {
        Some((t, c))
    } else {
        None
    }
}
