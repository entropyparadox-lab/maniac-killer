use crate::auth::Auth;
use crate::config::Config;
use crate::detector::TrackedProcess;
use crate::killer::KillResult;
use crate::notifier::urlencode;
use chrono::Utc;
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

        let server_name = config.get_server_name();
        let ssh_host = config.get_ssh_host();
        let now_ts = Utc::now().timestamp();

        let client = Client::new();

        // Generate HMAC-SHA256 Expiring Action Signatures (Valid for 15 mins)
        let kill_sig = Auth::sign_action(&config.auth_token, "kill", proc.pid, proc.start_time, now_ts);
        let kill_url = format!(
            "{}/confirm-kill?pid={}&st={}&ts={}&sig={}",
            base_url, proc.pid, proc.start_time, now_ts, kill_sig
        );

        let mute_sig = Auth::sign_action(&config.auth_token, "mute", proc.pid, proc.start_time, now_ts);
        let mute_url = format!(
            "{}/mute?pid={}&st={}&ts={}&sig={}&hours=1",
            base_url, proc.pid, proc.start_time, now_ts, mute_sig
        );

        let wl_sig = Auth::sign_action(&config.auth_token, "whitelist", proc.pid, proc.start_time, now_ts);
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

        let fallback_text = format!(
            "🚨 [MANIAC KILLER — {}] 폭주 프로세스 감지: {} (PID: {}, CPU: {:.1}%, MEM: {}MB)",
            server_name, proc.name, proc.pid, proc.cpu_percent, proc.memory_mb
        );

        let blocks = json!([
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": format!("🚨 [MANIAC KILLER] {} 폭주 프로세스 포착!", server_name),
                    "emoji": true
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": format!("*서버/장비:* `{}`", server_name)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*프로세스:* `{}` (PID: `{}`)", proc.name, proc.pid)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*CPU 점유율:* *`{:.1}%`* (연속 {}회)", proc.cpu_percent, proc.cpu_streak)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*메모리 점유:* *`{} MB`*", proc.memory_mb)
                    },
                    {
                        "type": "mrkdwn",
                        "text": format!("*사유:* {}", proc.reason)
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!("*📁 작업 경로:* `{}`\n*💻 실행 명령:* `{}`", if proc.cwd.is_empty() { "N/A" } else { &proc.cwd }, cmd_short)
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🩸 즉시 사살 (KILL)",
                            "emoji": true
                        },
                        "style": "danger",
                        "url": kill_url
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🛡️ 화이트리스트 등록",
                            "emoji": true
                        },
                        "url": wl_url
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "⏳ 1시간 침묵",
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
                        "text": format!("⚡ CLI 수동 사살: `ssh {} \"maniac-killer kill {}\"` | Claude CLI 세션 및 핵심 데몬은 절대 보호됩니다.", ssh_host, proc.pid)
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

        let server_name = config.get_server_name();
        let client = Client::new();
        let text = format!(
            "🩸 *[MANIAC KILLER — {}] 사살 보고서*\n• *PID:* `{}` ({})\n• *결과:* {}\n• *회수 메모리:* `{} MB`\n• *명령어:* `{}`",
            server_name, result.pid, result.name, result.message, result.memory_freed_mb, result.cmdline
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
