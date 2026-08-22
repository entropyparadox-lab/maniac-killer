use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use crate::notifier::urlencode;
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

        let client = Client::new();

        let kill_url = format!(
            "{}/kill?pid={}&token={}",
            base_url, proc.pid, config.auth_token
        );
        let mute_url = format!(
            "{}/mute?pid={}&hours=1&token={}",
            base_url, proc.pid, config.auth_token
        );
        let wl_url = format!(
            "{}/whitelist?name={}&token={}",
            base_url,
            urlencode(&proc.name),
            config.auth_token
        );

        let cmd_short = if proc.cmdline.len() > 180 {
            format!("{}...", &proc.cmdline[..180])
        } else {
            proc.cmdline.clone()
        };

        let payload = json!({
            "content": format!("🚨 **[MANIAC KILLER] Runaway Process Alert: `{}` (PID {})**", proc.name, proc.pid),
            "embeds": [
                {
                    "title": format!("🔥 Runaway Process Captured: {} (PID: {})", proc.name, proc.pid),
                    "color": 15158332, // Red
                    "fields": [
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
                        "text": "Maniac Killer Watchdog • AI Coding CLIs are strictly protected"
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

        let client = Client::new();
        let payload = json!({
            "embeds": [
                {
                    "title": format!("🩸 Execution Completed: {} (PID: {})", result.name, result.pid),
                    "description": &result.message,
                    "color": 3066993, // Green
                    "fields": [
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
