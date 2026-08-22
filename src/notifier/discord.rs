use crate::auth::Auth;
use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use crate::notifier::urlencode;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;

pub struct DiscordNotifier;

impl DiscordNotifier {
    pub async fn send_alert(
        config: &Config,
        proc: &TrackedProcess,
        base_url: &str,
    ) -> Result<(), String> {
        let webhook_url = match &config.discord_webhook_url {
            Some(u) if !u.is_empty() => u,
            _ => return Err("Discord Webhook URL not configured".to_string()),
        };

        let server_name = config.get_server_name();
        let ssh_host = config.get_ssh_host();
        let now_ts = Utc::now().timestamp();
        let client = Client::new();

        let kill_sig = Auth::sign_action(
            &config.auth_token,
            "kill",
            proc.pid,
            proc.start_time,
            now_ts,
        );
        let kill_url = format!(
            "{}/confirm-kill?pid={}&st={}&ts={}&sig={}",
            base_url, proc.pid, proc.start_time, now_ts, kill_sig
        );

        let mute_sig = Auth::sign_action(
            &config.auth_token,
            "mute",
            proc.pid,
            proc.start_time,
            now_ts,
        );
        let mute_url = format!(
            "{}/mute?pid={}&st={}&ts={}&sig={}&hours=1",
            base_url, proc.pid, proc.start_time, now_ts, mute_sig
        );

        let wl_sig = Auth::sign_action(
            &config.auth_token,
            "whitelist",
            proc.pid,
            proc.start_time,
            now_ts,
        );
        let wl_url = format!(
            "{}/whitelist?name={}&ts={}&sig={}",
            base_url,
            urlencode(&proc.name),
            now_ts,
            wl_sig
        );

        let cmd_short = if proc.cmdline.len() > 180 {
            format!("{}...", &proc.cmdline[..180])
        } else {
            proc.cmdline.clone()
        };

        let payload = json!({
            "content": format!("🚨 **[MANIAC KILLER — {}] Runaway Process Alert: `{}` (PID {})**", server_name, proc.name, proc.pid),
            "embeds": [
                {
                    "title": format!("🔥 Runaway Process Captured on {}: {} (PID: {})", server_name, proc.name, proc.pid),
                    "color": 15158332, // Red
                    "fields": [
                        { "name": "Server", "value": format!("`{}`", server_name), "inline": true },
                        { "name": "CPU Usage", "value": format!("**{:.1}%** (Streak: {})", proc.cpu_percent, proc.cpu_streak), "inline": true },
                        { "name": "Memory RSS", "value": format!("**{} MB**", proc.memory_mb), "inline": true },
                        { "name": "Reason", "value": &proc.reason, "inline": false },
                        { "name": "Working Directory", "value": if proc.cwd.is_empty() { "N/A" } else { &proc.cwd }, "inline": false },
                        { "name": "Command", "value": format!("`{}`", cmd_short), "inline": false },
                        {
                            "name": "⚡ Actions",
                            "value": format!("[🩸 **KILL NOW**]({}) • [🛡️ Whitelist]({}) • [⏳ Mute 1h]({})", kill_url, wl_url, mute_url),
                            "inline": false
                        }
                    ],
                    "footer": {
                        "text": format!("Maniac Killer Watchdog • CLI: ssh {} \"maniac-killer kill {}\"", ssh_host, proc.pid)
                    }
                }
            ]
        });

        let resp = client
            .post(webhook_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send Discord webhook: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Discord Webhook error status: {}", resp.status()));
        }

        Ok(())
    }

    pub async fn send_kill_report(config: &Config, result: &KillResult) -> Result<(), String> {
        let webhook_url = match &config.discord_webhook_url {
            Some(u) if !u.is_empty() => u,
            _ => return Err("Discord Webhook URL not configured".to_string()),
        };

        let server_name = config.get_server_name();
        let client = Client::new();
        let payload = json!({
            "embeds": [
                {
                    "title": format!("🩸 Execution Completed [{server_name}]: {} (PID: {})", result.name, result.pid),
                    "description": &result.message,
                    "color": 3066993, // Green
                    "fields": [
                        { "name": "Server", "value": format!("`{}`", server_name), "inline": true },
                        { "name": "Freed Memory", "value": format!("{} MB", result.memory_freed_mb), "inline": true },
                        { "name": "Command", "value": format!("`{}`", result.cmdline), "inline": false }
                    ]
                }
            ]
        });

        let _ = client.post(webhook_url).json(&payload).send().await;

        Ok(())
    }
}
