use crate::auth::{escape_html, Auth};
use crate::config::Config;
use crate::detector::Detector;
use crate::killer::Executioner;
use crate::notifier::Notifier;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
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
    pub st: Option<u64>,
    pub ts: Option<i64>,
    pub sig: Option<String>,
    pub token: Option<String>,
    pub name: Option<String>,
    pub hours: Option<i64>,
}

#[derive(Deserialize, Serialize)]
pub struct KillPayload {
    pub pid: u32,
    pub start_time: Option<u64>,
    pub timestamp: Option<i64>,
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct MutePayload {
    pub pid: u32,
    pub start_time: Option<u64>,
    pub timestamp: Option<i64>,
    pub hours: Option<i64>,
    pub token: String,
}

#[derive(Deserialize, Serialize)]
pub struct WhitelistPayload {
    pub name: String,
    pub timestamp: Option<i64>,
    pub token: String,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/health", get(handle_health))
        .route("/kill", get(handle_confirm_kill_ui))
        .route("/confirm-kill", get(handle_confirm_kill_ui))
        .route("/mute", get(handle_mute_ui))
        .route("/whitelist", get(handle_whitelist_ui))
        .route("/api/kill", post(handle_api_kill))
        .route("/api/mute", post(handle_api_mute))
        .route("/api/whitelist", post(handle_api_whitelist))
        .route("/api/status", get(handle_status_api))
        .with_state(state)
}

async fn handle_health() -> &'static str {
    "OK (Maniac Killer Watchdog Online)"
}

async fn handle_dashboard(State(state): State<AppState>) -> Html<String> {
    let detector = state.detector.lock().await;
    let mut rows = String::new();
    let server_name = state.config.get_server_name();
    let now_ts = Utc::now().timestamp();

    for proc in detector.tracked.values() {
        let sig = Auth::sign_action(
            &state.config.auth_token,
            "kill",
            proc.pid,
            proc.start_time,
            now_ts,
        );
        rows.push_str(&format!(
            "<tr>
                <td><b>{}</b></td>
                <td><code>{}</code></td>
                <td style='color:#ff5555;'><b>{:.1}%</b> (streak: {})</td>
                <td>{} MB</td>
                <td>{}</td>
                <td><small><code>{}</code></small></td>
                <td>
                    <a href='/confirm-kill?pid={}&st={}&ts={}&sig={}' style='background:#ff5555;color:#fff;padding:6px 12px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block;'>🩸 KILL</a>
                </td>
            </tr>",
            proc.pid,
            escape_html(&proc.name),
            proc.cpu_percent,
            proc.cpu_streak,
            proc.memory_mb,
            escape_html(&proc.reason),
            escape_html(&proc.cwd),
            proc.pid,
            proc.start_time,
            now_ts,
            sig
        ));
    }

    if rows.is_empty() {
        rows = "<tr><td colspan='7' style='text-align:center;padding:30px;color:#50fa7b;'><b>✨ No runaway processes detected. System running fast & clean.</b></td></tr>".to_string();
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>🔪 MANIAC KILLER — {} Control Center</title>
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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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
        }}
        .server-badge {{
            background: #1f6feb;
            color: #fff;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: bold;
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
        }}
        tr:hover {{
            background: #1f242c;
        }}
        .footer {{
            margin-top: 30px;
            font-size: 13px;
            color: #8b949e;
        }}
        code {{
            background: #21262d;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🩸 MANIAC KILLER <span class="badge">ONLINE</span></h1>
            <div style="font-size: 13px; color: #8b949e; display: flex; align-items: center; gap: 10px;">
                <span class="server-badge">Host: {}</span>
                <span>Threshold: <b>{:.0}% CPU</b> (Streak: {})</span>
            </div>
        </header>
        <p style="margin-top: 0; color: #8b949e;">Runaway process watchdog and remote executioner for <b>{}</b> with native AI agent immunity.</p>
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
        escape_html(&server_name),
        escape_html(&server_name),
        state.config.cpu_threshold,
        state.config.cpu_streak,
        escape_html(&server_name),
        rows
    );

    Html(html)
}

/// Renders a secure Confirmation UI before triggering POST execution (Prevents Link Prefetch accidental kills)
async fn handle_confirm_kill_ui(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let auth_token = query
        .sig
        .as_deref()
        .or(query.token.as_deref())
        .unwrap_or_default();
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "kill",
        query.pid,
        query.st,
        query.ts,
        auth_token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<div style='font-family:sans-serif;margin:60px auto;max-width:500px;background:#161b22;padding:30px;border-radius:8px;color:#ff7b72;border:1px solid #ff7b72;'><h2>⛔ Unauthorized</h2><p>Invalid or expired authentication signature / token.</p></div>".to_string())
        );
    }

    let pid = match query.pid {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html("<h2>Missing PID parameter</h2>".to_string()),
            )
        }
    };

    let st = query.st.unwrap_or(0);
    let ts = query.ts.unwrap_or(0);

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>🩸 Confirm Process Execution — Maniac Killer</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 60px 20px;
            display: flex;
            justify-content: center;
        }}
        .card {{
            max-width: 520px;
            width: 100%;
            background: #161b22;
            padding: 36px;
            border-radius: 12px;
            border: 1px solid #30363d;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }}
        h2 {{ color: #ff5555; margin-top: 0; font-size: 22px; display: flex; align-items: center; gap: 8px; }}
        .btn-kill {{
            width: 100%;
            background: #da3633;
            color: #fff;
            border: none;
            padding: 14px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
            margin-top: 20px;
        }}
        .btn-kill:hover {{ background: #f85149; }}
        .info-box {{
            background: #21262d;
            padding: 16px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 14px;
            line-height: 1.6;
        }}
        code {{ color: #8be9fd; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="card">
        <h2>🩸 Confirm Process Termination</h2>
        <p>Are you sure you want to execute process tree for <b>PID <code>{}</code></b>?</p>
        
        <div class="info-box">
            • <b>Target PID:</b> <code>{}</code><br>
            • <b>Process Start Time:</b> <code>{}</code><br>
            • <b>Method:</b> Recursive Tree-Kill (SIGTERM ➡️ SIGKILL)<br>
            • <b>Security:</b> HMAC-SHA256 Signed Execution
        </div>

        <form method="POST" action="/api/kill">
            <input type="hidden" name="pid" value="{}">
            <input type="hidden" name="start_time" value="{}">
            <input type="hidden" name="timestamp" value="{}">
            <input type="hidden" name="token" value="{}">
            <button type="submit" class="btn-kill">🩸 EXECUTE & TERMINATE TREE</button>
        </form>

        <p style="margin-top: 20px; text-align: center; font-size: 13px;">
            <a href="/" style="color: #8b949e; text-decoration: none;">Cancel and return to Dashboard</a>
        </p>
    </div>
</body>
</html>"#,
        pid,
        pid,
        st,
        pid,
        st,
        ts,
        escape_html(auth_token)
    );

    (StatusCode::OK, Html(html))
}

/// Secure POST API for Process Termination with TOCTOU + Agent Immunity verification
async fn handle_api_kill(
    State(state): State<AppState>,
    axum::extract::Form(payload): axum::extract::Form<KillPayload>,
) -> impl IntoResponse {
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "kill",
        Some(payload.pid),
        payload.start_time,
        payload.timestamp,
        &payload.token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<h2>⛔ Unauthorized: Invalid or expired execution token</h2>".to_string()),
        );
    }

    let whitelist = {
        let detector = state.detector.lock().await;
        detector.whitelist.clone()
    };

    match Executioner::execute(payload.pid, payload.start_time, &whitelist).await {
        Ok(result) => {
            Notifier::dispatch_kill_report(&state.config, &result).await;
            (
                StatusCode::OK,
                Html(format!(
                    r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                    <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #238636;">
                        <h2 style="color:#50fa7b;margin-top:0;">🩸 Execution Completed</h2>
                        <p><b>Target:</b> <code>{}</code> (PID: {})</p>
                        <p><b>Result:</b> {}</p>
                        <p><b>Freed Memory:</b> {} MB</p>
                        <p><b>Terminated PIDs:</b> {:?}</p>
                        <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                        <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                    </div></body></html>"#,
                    escape_html(&result.name),
                    result.pid,
                    escape_html(&result.message),
                    result.memory_freed_mb,
                    result.killed_pids
                )),
            )
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Html(format!(
                r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #ff5555;">
                    <h2 style="color:#ff5555;margin-top:0;">🛡️ Execution Rejected</h2>
                    <p>{}</p>
                    <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                    <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                </div></body></html>"#,
                escape_html(&err)
            )),
        ),
    }
}

async fn handle_mute_ui(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let auth_token = query
        .sig
        .as_deref()
        .or(query.token.as_deref())
        .unwrap_or_default();
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "mute",
        query.pid,
        query.st,
        query.ts,
        auth_token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<h2>⛔ Unauthorized Signature</h2>".to_string()),
        );
    }

    if let Some(pid) = query.pid {
        let hours = query.hours.unwrap_or(1);
        let mut detector = state.detector.lock().await;
        detector.mute(pid, hours);
        (
            StatusCode::OK,
            Html(format!(
                r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #30363d;">
                    <h2 style="color:#f0f6fc;margin-top:0;">⏳ Muted for {} hour(s)</h2>
                    <p>Alerts for PID <b>{}</b> have been silenced.</p>
                    <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                    <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                </div></body></html>"#,
                hours, pid
            )),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Html("<h2>Missing PID</h2>".to_string()),
        )
    }
}

async fn handle_whitelist_ui(
    Query(query): Query<ActionQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let auth_token = query
        .sig
        .as_deref()
        .or(query.token.as_deref())
        .unwrap_or_default();
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "whitelist",
        query.pid,
        query.st,
        query.ts,
        auth_token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Html("<h2>⛔ Unauthorized Signature</h2>".to_string()),
        );
    }

    if let Some(name) = query.name {
        let mut detector = state.detector.lock().await;
        detector.add_whitelist(name.clone());
        (
            StatusCode::OK,
            Html(format!(
                r#"<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:60px 20px;display:flex;justify-content:center;">
                <div style="max-width:500px;width:100%;background:#161b22;padding:30px;border-radius:10px;border:1px solid #30363d;">
                    <h2 style="color:#50fa7b;margin-top:0;">🛡️ Added to Whitelist</h2>
                    <p>Keyword <code>{}</code> is now permanently immune during this session.</p>
                    <hr style="border:0;border-top:1px solid #30363d;margin:20px 0;">
                    <a href="/" style="color:#8be9fd;text-decoration:none;font-weight:bold;">⬅️ Return to Dashboard</a>
                </div></body></html>"#,
                escape_html(&name)
            )),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Html("<h2>Missing Name</h2>".to_string()),
        )
    }
}

async fn handle_api_mute(
    State(state): State<AppState>,
    Json(payload): Json<MutePayload>,
) -> impl IntoResponse {
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "mute",
        Some(payload.pid),
        payload.start_time,
        payload.timestamp,
        &payload.token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    }

    let hours = payload.hours.unwrap_or(1);
    let mut detector = state.detector.lock().await;
    detector.mute(payload.pid, hours);
    (
        StatusCode::OK,
        Json(json!({"ok": true, "pid": payload.pid, "muted_hours": hours})),
    )
}

async fn handle_api_whitelist(
    State(state): State<AppState>,
    Json(payload): Json<WhitelistPayload>,
) -> impl IntoResponse {
    let is_auth = Auth::is_authorized(
        &state.config.auth_token,
        "whitelist",
        None,
        None,
        payload.timestamp,
        &payload.token,
    );

    if !is_auth {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        );
    }

    let mut detector = state.detector.lock().await;
    detector.add_whitelist(payload.name.clone());
    (
        StatusCode::OK,
        Json(json!({"ok": true, "whitelisted": payload.name})),
    )
}

async fn handle_status_api(State(state): State<AppState>) -> Json<serde_json::Value> {
    let detector = state.detector.lock().await;
    let list: Vec<_> = detector.tracked.values().cloned().collect();
    let server_name = state.config.get_server_name();
    Json(json!({
        "server_name": server_name,
        "tracked_count": list.len(),
        "processes": list
    }))
}
