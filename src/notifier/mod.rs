pub mod discord;
pub mod slack;
pub mod telegram;

use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use tracing::error;

pub struct Notifier;

impl Notifier {
    pub async fn dispatch_alert(config: &Config, proc: &TrackedProcess, base_url: &str) {
        // 1. Slack
        if config.slack_bot_token.is_some() && config.slack_channel.is_some() {
            if let Err(e) = slack::SlackNotifier::send_alert(config, proc, base_url).await {
                error!("Failed to send Slack alert: {}", e);
            }
        }

        // 2. Discord
        if config.discord_webhook_url.is_some() {
            if let Err(e) = discord::DiscordNotifier::send_alert(config, proc, base_url).await {
                error!("Failed to send Discord alert: {}", e);
            }
        }

        // 3. Telegram
        if config.telegram_bot_token.is_some() && config.telegram_chat_id.is_some() {
            if let Err(e) = telegram::TelegramNotifier::send_alert(config, proc, base_url).await {
                error!("Failed to send Telegram alert: {}", e);
            }
        }
    }

    pub async fn dispatch_kill_report(config: &Config, result: &KillResult) {
        if config.slack_bot_token.is_some() && config.slack_channel.is_some() {
            let _ = slack::SlackNotifier::send_kill_report(config, result).await;
        }
        if config.discord_webhook_url.is_some() {
            let _ = discord::DiscordNotifier::send_kill_report(config, result).await;
        }
        if config.telegram_bot_token.is_some() && config.telegram_chat_id.is_some() {
            let _ = telegram::TelegramNotifier::send_kill_report(config, result).await;
        }
    }
}

pub fn urlencode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}
