use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use crate::notifier::urlencode;
use reqwest::Client;
use serde_json::json;

pub struct SlackNotifier;

impl SlackNotifier {
    pub async fn send_alert(
        config: &Config,
        proc: &TrackedProcess,
        base_url: &str,
    ) -> Result<(), String> {
        let token = match &config.slack_bot_token {
            Some(t) if !t.is_empty() => t,
            _ => return Err("Slack Bot Token not configured".to_string()),
        };
        let channel = match &config.slack_channel {
            Some(c) if !c.is_empty() => c,
            _ => return Err("Slack Channel not configured".to_string()),
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

        let fallback_text = format!(
            "🚨 [MANIAC KILLER] Runaway Process Detected: {} (PID: {}, CPU: {:.1}%, MEM: {}MB)",
            proc.name, proc.pid, proc.cpu_percent, proc.memory_mb
        );

        let blocks = json!([
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 [MANIAC KILLER] Runaway Process Captured!",
                    "emoji": true
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": format!("*Process:* `{}` (PID: `{}`)", proc.name, proc.pid)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*CPU Usage:* *`{:.1}%`* (streak: {})", proc.cpu_percent, proc.cpu_streak)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Memory RSS:* *`{} MB`*", proc.memory_mb)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*Reason:* {}", proc.reason)
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*📁 Working Dir:* `{}`\n*💻 Command:* `{}`", if proc.cwd.is_empty() { "N/A" } else { &proc.cwd }, cmd_short)
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🩸 KILL NOW",
                            "emoji": true
                        },
                        "style": "danger",
                        "url": kill_url
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🛡️ Whitelist",
                            "emoji": true
                        },
                        "url": wl_url
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "⏳ Mute 1h",
                            "emoji": true
                        },
                        "url": mute_url
                    }
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": format!("⚡ CLI Quick Kill: `maniac-killer kill {}` | AI Coding & System Daemons are strictly protected.", proc.pid)
                    }
                ]
            }
        ]);

        let payload = json!({
            "channel": channel,
            "text": fallback_text,
            "blocks": blocks
        });

        let resp = client
            .post("https://slack.com/api/chat.postMessage")
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to send Slack request: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Slack API error status: {}", resp.status()));
        }

        let resp_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Slack response: {}", e))?;

        if !resp_json
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err(format!(
                "Slack API returned not ok: {:?}",
                resp_json.get("error")
            ));
        }

        Ok(())
    }

    pub async fn send_kill_report(config: &Config, result: &KillResult) -> Result<(), String> {
        let token = match &config.slack_bot_token {
            Some(t) if !t.is_empty() => t,
            _ => return Err("Slack Bot Token not configured".to_string()),
        };
        let channel = match &config.slack_channel {
            Some(c) if !c.is_empty() => c,
            _ => return Err("Slack Channel not configured".to_string()),
        };

        let client = Client::new();
        let text = format!(
            "🩸 *[MANIAC KILLER] Execution Report*\n• *PID:* `{}` ({})\n• *Status:* {}\n• *Freed Memory:* `{} MB`\n• *Command:* `{}`",
            result.pid, result.name, result.message, result.memory_freed_mb, result.cmdline
        );

        let payload = json!({
            "channel": channel,
            "text": text
        });

        let _ = client
            .post("https://slack.com/api/chat.postMessage")
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send()
            .await;

        Ok(())
    }
}
