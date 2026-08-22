use crate::config::Config;
use crate::detector::Detector;
use crate::killer::Executioner;
use crate::notifier::Notifier;
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub detector: Arc<Mutex<Detector>>,
}

#[derive(Deserialize)]
pub struct ActionQuery {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub hours: Option<i64>,
    pub token: String,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/health", get(handle_health))
        .route("/kill", get(handle_kill))
        .route("/mute", get(handle_mute))
        .route("/whitelist", get(handle_whitelist))
        .route("/api/status", get(handle_status_api))
        .with_state(state)
}

async fn handle_health() -> &'static str {
    "OK (Maniac Killer Watchdog Online)"
}

async fn handle_dashboard(State(state): State<AppState>) -> Html<String> {
    let detector = state.detector.lock().await;
    let mut rows = String::new();
    for (_, proc) in &detector.tracked {
        rows.push_str(&format!(
            "<tr>
                <td><b>{}</b></td>
                <td><code>{}</code></td>
                <td style='color:#ff5555;'><b>{:.1}%</b> (streak: {})</td>
                <td>{} MB</td>
                <td>{}</td>
                <td><small><code>{}</code></small></td>
                <td>
                    <a href='/kill?pid={}&token={}' style='background:#ff5555;color:#fff;padding:6px 12px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;'>🩸 KILL</a>
                </td>
            </tr>",
            proc.pid, proc.name, proc.cpu_percent, proc.cpu_streak, proc.memory_mb, proc.reason, proc.cwd, proc.pid, state.config.auth_token
        ));
    }

    if rows.is_empty() {
        rows = "<tr><td colspan='7' style='text-align:center;padding:30px;color:#50fa7b;'><b>✨ No runaway or orphaned processes detected. System is running calm and fast.</b></td></tr>".to_string();
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>🔪 MANIAC KILLER — System Control Center</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --accent-red: #ff5555;
            --accent-green: #50fa7b;
            --accent-cyan: #8be9fd;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 40px 20px;
            display: flex;
            justify-content: center;
        }}
        .container {{
            max-width: 1050px;
            width: 100%;
        }}
        header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
        }}
        h1 {{
            margin: 0;
            font-size: 26px;
            color: #f0f6fc;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .badge {{
            background: #238636;
            color: #fff;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border);
            margin-top: 16px;
        }}
        th, td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }}
        th {{
            background: #21262d;
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background: #1f242c;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 13px;
            color: #8b949e;
            line-height: 1.6;
        }}
        code {{
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🩸 MANIAC KILLER <span class="badge">ONLINE</span></h1>
            <div style="font-size: 13px; color: #8b949e;">Threshold: <b>{:.0}% CPU</b> (Streak: {})</div>
        </header>
        <p style="margin-top: 0; color: #8b949e;">Runaway process watchdog and remote executioner with native AI agent immunity.</p>
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>CPU Load</th>
                    <th>Memory</th>
                    <th>Reason</th>
                    <th>Working Directory</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
        <div class="footer">
            <p>🛡️ <b>Immunity Guarantee:</b> Active Claude Code sessions, AI developer tools, and critical system/kernel daemons are strictly protected by built-in immune rules.</p>
        </div>
    </div>
</body>
</html>"#,
        state.config.cpu_threshold, state.config.cpu_streak, rows
    );

    Html(html)
}

async fn handle_kill(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if query.token != state.config.auth_token {
        return Html("<div style='font-family:sans-serif;margin:60px auto;max-width:500px;background:#161b22;padding:30px;border-radius:8px;color:#ff7b72;border:1px solid #ff7b72;'><h2>⛔ Unauthorized</h2><p>Invalid or missing authentication token.</p></div>".to_string());
    }

    let pid = match query.pid {
        Some(p) => p,
        None => return Html("<div style='font-family:sans-serif;margin:60px auto;max-width:500px;background:#161b22;padding:30px;border-radius:8px;color:#f0f6fc;'><h2>⚠️ Missing PID</h2></div>".to_string()),
    };

    let whitelist = {
        let detector = state.detector.lock().await;
        detector.whitelist.clone()
    };

    match Executioner::execute(pid, &whitelist) {
        Ok(result) => {
            // Dispatch kill report to all configured channels
            Notifier::dispatch_kill_report(&state.config, &result).await;
            Html(format!(
                r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #238636;">
                    <h2 style="color:#50fa7b;margin-top:0;">🩸 Execution Completed</h2>
                    <p><b>Target:</b> <code>{}</code> (PID: {})</p>
                    <p><b>Result:</b> {}</p>
                    <p><b>Freed Memory:</b> {} MB</p>
                    <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                    <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                </div></body></html>"#,
                result.name, result.pid, result.message, result.memory_freed_mb
            ))
        }
        Err(err) => Html(format!(
            r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #ff5555;">
                    <h2 style="color:#ff5555;margin-top:0;">🛡️ Execution Rejected (Protected)</h2>
                    <p>{}</p>
                    <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                    <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                </div></body></html>"#,
            err
        )),
    }
}

async fn handle_mute(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if query.token != state.config.auth_token {
        return Html("<h2>⛔ Unauthorized</h2>".to_string());
    }

    if let Some(pid) = query.pid {
        let hours = query.hours.unwrap_or(1);
        let mut detector = state.detector.lock().await;
        detector.mute(pid, hours);
        Html(format!(
            r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
            <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #30363d;">
                <h2 style="color:#f0f6fc;margin-top:0;">⏳ Muted for {} hour(s)</h2>
                <p>Alerts for PID {} have been silenced.</p>
                <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
            </div></body></html>"#,
            hours, pid
        ))
    } else {
        Html("<h2>Missing PID</h2>".to_string())
    }
}

async fn handle_whitelist(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if query.token != state.config.auth_token {
        return Html("<h2>⛔ Unauthorized</h2>".to_string());
    }

    if let Some(name) = query.name {
        let mut detector = state.detector.lock().await;
        detector.add_whitelist(name.clone());
        Html(format!(
            r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
            <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #30363d;">
                <h2 style="color:#50fa7b;margin-top:0;">🛡️ Added to Whitelist</h2>
                <p>Keyword <code>{}</code> is now permanently immune during this session.</p>
                <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
            </div></body></html>"#,
            name
        ))
    } else {
        Html("<h2>Missing Name</h2>".to_string())
    }
}

async fn handle_status_api(State(state): State<AppState>) -> Json<serde_json::Value> {
    let detector = state.detector.lock().await;
    let list: Vec<_> = detector.tracked.values().cloned().collect();
    Json(json!({
        "tracked_count": list.len(),
        "processes": list
    }))
}
