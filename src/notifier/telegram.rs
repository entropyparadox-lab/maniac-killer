use crate::auth::Auth;
use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use crate::notifier::urlencode;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;

pub struct TelegramNotifier;

impl TelegramNotifier {
    pub async fn send_alert(
        config: &Config,
        proc: &TrackedProcess,
        base_url: &str,
    ) -> Result<(), String> {
        let bot_token = match &config.telegram_bot_token {
            Some(t) if !t.is_empty() => t,
            _ => return Err("Telegram Bot Token not configured".to_string()),
        };
        let chat_id = match &config.telegram_chat_id {
            Some(c) if !c.is_empty() => c,
            _ => return Err("Telegram Chat ID not configured".to_string()),
        };

        let server_name = config.get_server_name();
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

        let cmd_short = if proc.cmdline.len() > 140 {
            format!("{}...", &proc.cmdline[..140])
        } else {
            proc.cmdline.clone()
        };

        let text = format!(
            "🚨 *[MANIAC KILLER — {}] Runaway Process Alert*\n\n\
            • *Server:* `{}`\n\
            • *Process:* `{}` (PID `{}`)\n\
            • *CPU:* *`{:.1}%`* (streak {})\n\
            • *Memory:* *`{} MB`*\n\
            • *Reason:* {}\n\
            • *CWD:* `{}`\n\
            • *Command:* `{}`",
            server_name,
            server_name,
            proc.name,
            proc.pid,
            proc.cpu_percent,
            proc.cpu_streak,
            proc.memory_mb,
            proc.reason,
            if proc.cwd.is_empty() {
                "N/A"
            } else {
                &proc.cwd
            },
            cmd_short
        );

        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": {
                "inline_keyboard": [
                    [
                        { "text": "🩸 KILL NOW", "url": kill_url },
                        { "text": "🛡️ Whitelist", "url": wl_url },
                        { "text": "⏳ Mute 1h", "url": mute_url }
                    ]
                ]
            }
        });

        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send Telegram message: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Telegram API error status: {}", resp.status()));
        }

        Ok(())
    }

    pub async fn send_kill_report(config: &Config, result: &KillResult) -> Result<(), String> {
        let bot_token = match &config.telegram_bot_token {
            Some(t) if !t.is_empty() => t,
            _ => return Err("Telegram Bot Token not configured".to_string()),
        };
        let chat_id = match &config.telegram_chat_id {
            Some(c) if !c.is_empty() => c,
            _ => return Err("Telegram Chat ID not configured".to_string()),
        };

        let server_name = config.get_server_name();
        let client = Client::new();
        let text = format!(
            "🩸 *[MANIAC KILLER — {}] Execution Report*\n\n\
            • *PID:* `{}` ({})\n\
            • *Status:* {}\n\
            • *Freed Memory:* `{} MB`\n\
            • *Command:* `{}`",
            server_name,
            result.pid,
            result.name,
            result.message,
            result.memory_freed_mb,
            result.cmdline
        );

        let payload = json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown"
        });

        let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
        let _ = client.post(&url).json(&payload).send().await;

        Ok(())
    }
}
