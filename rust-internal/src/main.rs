mod config;
mod crypto;
mod identity;
mod models;
mod session;

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::sync::Mutex;

use config::Config;
use models::{SessionContext, SessionResult};

// ── Embedded static files ───────────────────────────────

const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLE_CSS: &str = include_str!("../static/css/style.css");

// ── Journey State ───────────────────────────────────────

struct JourneyState {
    config: Config,
    http_client: reqwest::Client,
    session: Option<SessionContext>,
    access_token: String,
    refresh_token: String,
}

type AppState = Arc<Mutex<JourneyState>>;

// ── Main ────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let config = Config::load();
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--cli") {
        run_cli(config).await;
        return;
    }

    let port = config.port;
    let state: AppState = Arc::new(Mutex::new(JourneyState {
        config,
        http_client: reqwest::Client::new(),
        session: None,
        access_token: String::new(),
        refresh_token: String::new(),
    }));

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/css/style.css", get(serve_css))
        .route("/steps/1", post(step_1))
        .route("/steps/2", post(step_2))
        .route("/steps/3", post(step_3))
        .route("/steps/4", post(step_4))
        .route("/steps/5", post(step_5))
        .route("/steps/6", post(step_6))
        .route("/steps/reset", post(step_reset))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    println!();
    println!("  Identity Service — Internal Client Example (Rust)");
    println!("  Web UI:  http://localhost:{port}");
    println!("  API:     /steps/1..6 → Rust crypto → Sidecar");
    println!("  Auth:    Basic Auth");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ── Static file handlers ────────────────────────────────

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_css() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css")], STYLE_CSS)
}

// ── Step handlers ───────────────────────────────────────

async fn step_1(State(state): State<AppState>) -> impl IntoResponse {
    let mut s = state.lock().await;
    let start = Instant::now();
    match session::init_session(&s.config, &s.http_client).await {
        Ok(ctx) => {
            let result = SessionResult {
                step: 1,
                name: "Session Init (Anonymous ECDH)".into(),
                success: true,
                duration_ms: start.elapsed().as_millis(),
                session_id: ctx.session_id.clone(),
                kid: ctx.kid.clone(),
                authenticated: ctx.authenticated,
                expires_in_sec: ctx.expires_in_sec,
                error: None,
            };
            s.session = Some(ctx);
            s.access_token.clear();
            s.refresh_token.clear();
            Json(serde_json::to_value(result).unwrap())
        }
        Err(e) => {
            let result = SessionResult {
                step: 1,
                name: "Session Init (Anonymous ECDH)".into(),
                success: false,
                duration_ms: start.elapsed().as_millis(),
                session_id: String::new(),
                kid: String::new(),
                authenticated: false,
                expires_in_sec: 0,
                error: Some(e),
            };
            Json(serde_json::to_value(result).unwrap())
        }
    }
}

async fn step_2(State(state): State<AppState>) -> impl IntoResponse {
    let mut s = state.lock().await;
    let session = match &s.session {
        Some(sess) => sess,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Run step 1 first"})),
            );
        }
    };

    let body = serde_json::json!({
        "audience": "orders-api",
        "scope": "orders.read orders.write",
        "subject": s.config.subject,
        "include_refresh_token": true,
        "single_session": true,
        "custom_claims": { "roles": "admin", "tenant": "test-corp" }
    })
    .to_string();

    let result = identity::issue_token(&s.config, &s.http_client, session, &body).await;

    if result.success {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&result.response_body_decrypted)
        {
            if let Some(at) = data.get("access_token").and_then(|v| v.as_str()) {
                s.access_token = at.to_string();
            }
            if let Some(rt) = data.get("refresh_token").and_then(|v| v.as_str()) {
                s.refresh_token = rt.to_string();
            }
        }
    }

    (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
}

async fn step_3(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.lock().await;
    let session = match &s.session {
        Some(sess) => sess,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Run steps 1-2 first"})),
            );
        }
    };
    if s.access_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Run steps 1-2 first"})),
        );
    }

    let body = serde_json::json!({ "token": s.access_token }).to_string();
    let result = identity::introspect_token(
        &s.config,
        &s.http_client,
        session,
        &body,
        &s.access_token,
    )
    .await;

    (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
}

async fn step_4(State(state): State<AppState>) -> impl IntoResponse {
    let mut s = state.lock().await;
    if s.session.is_none() || s.access_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Run steps 1-3 first"})),
        );
    }

    let start = Instant::now();
    let access_token = s.access_token.clone();
    let mut old_session = s.session.take();
    match session::refresh_session(&s.config, &s.http_client, &access_token, &mut old_session)
        .await
    {
        Ok(ctx) => {
            let result = SessionResult {
                step: 4,
                name: "Session Refresh (Authenticated ECDH)".into(),
                success: true,
                duration_ms: start.elapsed().as_millis(),
                session_id: ctx.session_id.clone(),
                kid: ctx.kid.clone(),
                authenticated: ctx.authenticated,
                expires_in_sec: ctx.expires_in_sec,
                error: None,
            };
            s.session = Some(ctx);
            (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
        }
        Err(e) => {
            let result = SessionResult {
                step: 4,
                name: "Session Refresh (Authenticated ECDH)".into(),
                success: false,
                duration_ms: start.elapsed().as_millis(),
                session_id: String::new(),
                kid: String::new(),
                authenticated: false,
                expires_in_sec: 0,
                error: Some(e),
            };
            (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
        }
    }
}

async fn step_5(State(state): State<AppState>) -> impl IntoResponse {
    let mut s = state.lock().await;
    let session = match &s.session {
        Some(sess) => sess,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Run steps 1-4 first"})),
            );
        }
    };
    if s.access_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Run steps 1-4 first"})),
        );
    }

    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": s.refresh_token
    })
    .to_string();

    let result =
        identity::refresh_token(&s.config, &s.http_client, session, &body, &s.access_token).await;

    if result.success {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&result.response_body_decrypted)
        {
            if let Some(at) = data.get("access_token").and_then(|v| v.as_str()) {
                s.access_token = at.to_string();
            }
            if let Some(rt) = data.get("refresh_token").and_then(|v| v.as_str()) {
                s.refresh_token = rt.to_string();
            }
        }
    }

    (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
}

async fn step_6(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.lock().await;
    let session = match &s.session {
        Some(sess) => sess,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Run steps 1-5 first"})),
            );
        }
    };
    if s.access_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Run steps 1-5 first"})),
        );
    }

    let body = serde_json::json!({
        "token": s.refresh_token,
        "token_type_hint": "refresh_token"
    })
    .to_string();

    let result =
        identity::revoke_token(&s.config, &s.http_client, session, &body, &s.access_token).await;

    (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
}

async fn step_reset(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut s = state.lock().await;
    if let Some(ref mut sess) = s.session {
        sess.zeroize();
    }
    s.session = None;
    s.access_token.clear();
    s.refresh_token.clear();
    Json(serde_json::json!({"success": true}))
}

// ── CLI Runner ──────────────────────────────────────────

async fn run_cli(config: Config) {
    const RESET: &str = "\x1b[0m";
    const BOLD: &str = "\x1b[1m";
    const DIM: &str = "\x1b[2m";
    const BLUE: &str = "\x1b[34m";
    const GREEN: &str = "\x1b[32m";
    const RED: &str = "\x1b[31m";
    const CYAN: &str = "\x1b[36m";
    let http_client = reqwest::Client::new();
    let client_id = config.client_id.clone();

    println!();
    println!("{BLUE}{BOLD}  ╔══════════════════════════════════════════════════╗{RESET}");
    println!("{BLUE}{BOLD}  ║  Identity Service — Internal Client (Rust)       ║{RESET}");
    println!("{BLUE}{BOLD}  ║  Auth: Basic Auth + AES-256-GCM                  ║{RESET}");
    println!(
        "{BLUE}{BOLD}  ║  Client: {:<40} ║{RESET}",
        client_id
    );
    println!("{BLUE}{BOLD}  ╚══════════════════════════════════════════════════╝{RESET}");
    println!();

    // Step 1: Session Init
    println!("{CYAN}{BOLD}  ── Step 1: Session Init (Anonymous ECDH) ──{RESET}");
    let mut sess = match session::init_session(&config, &http_client).await {
        Ok(s) => s,
        Err(e) => {
            println!("{RED}    ✗ {e}{RESET}");
            return;
        }
    };
    println!("{GREEN}    ✓ Session established{RESET}");
    println!("{DIM}    SessionId: {}{RESET}", sess.session_id);
    println!("{DIM}    Kid:       {}{RESET}", sess.kid);
    println!(
        "{DIM}    TTL:       {}s ({}){RESET}",
        sess.expires_in_sec,
        if sess.authenticated {
            "authenticated"
        } else {
            "anonymous"
        }
    );
    println!();

    // Step 2: Token Issue
    println!("{CYAN}{BOLD}  ── Step 2: Token Issue (Basic Auth + GCM) ──{RESET}");
    let issue_body = serde_json::json!({
        "audience": "orders-api",
        "scope": "orders.read orders.write",
        "subject": config.subject,
        "include_refresh_token": true,
        "single_session": true,
        "custom_claims": { "roles": "admin", "tenant": "test-corp" }
    })
    .to_string();
    let issue_result = identity::issue_token(&config, &http_client, &sess, &issue_body).await;
    print_result(&issue_result);
    if !issue_result.success {
        return;
    }
    let issue_data: serde_json::Value =
        serde_json::from_str(&issue_result.response_body_decrypted).unwrap();
    let mut access_token = issue_data["access_token"].as_str().unwrap().to_string();
    let mut refresh_token = issue_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Step 3: Token Introspection
    println!("{CYAN}{BOLD}  ── Step 3: Token Introspection (Bearer + GCM) ──{RESET}");
    let intro_body = serde_json::json!({ "token": access_token }).to_string();
    let intro_result =
        identity::introspect_token(&config, &http_client, &sess, &intro_body, &access_token).await;
    print_result(&intro_result);
    if !intro_result.success {
        return;
    }

    // Step 4: Session Refresh
    println!("{CYAN}{BOLD}  ── Step 4: Session Refresh (Authenticated ECDH) ──{RESET}");
    let mut old_session = Some(sess);
    sess = match session::refresh_session(&config, &http_client, &access_token, &mut old_session)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            println!("{RED}    ✗ {e}{RESET}");
            return;
        }
    };
    println!("{GREEN}    ✓ Session refreshed{RESET}");
    println!("{DIM}    SessionId: {}{RESET}", sess.session_id);
    println!(
        "{DIM}    TTL:       {}s (authenticated){RESET}",
        sess.expires_in_sec
    );
    println!();

    // Step 5: Token Refresh
    println!("{CYAN}{BOLD}  ── Step 5: Token Refresh (Bearer + GCM) ──{RESET}");
    let refresh_body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    })
    .to_string();
    let refresh_result =
        identity::refresh_token(&config, &http_client, &sess, &refresh_body, &access_token).await;
    print_result(&refresh_result);
    if !refresh_result.success {
        return;
    }
    let refresh_data: serde_json::Value =
        serde_json::from_str(&refresh_result.response_body_decrypted).unwrap();
    access_token = refresh_data["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    refresh_token = refresh_data
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Step 6: Token Revocation
    println!("{CYAN}{BOLD}  ── Step 6: Token Revocation (Bearer + GCM) ──{RESET}");
    let revoke_body = serde_json::json!({
        "token": refresh_token,
        "token_type_hint": "refresh_token"
    })
    .to_string();
    let revoke_result =
        identity::revoke_token(&config, &http_client, &sess, &revoke_body, &access_token).await;
    print_result(&revoke_result);

    // Cleanup
    sess.zeroize();
    println!("{GREEN}{BOLD}  All 6 steps completed successfully!{RESET}");
    println!();

    fn print_result(r: &models::StepResult) {
        const RESET: &str = "\x1b[0m";
        const DIM: &str = "\x1b[2m";
        const GREEN: &str = "\x1b[32m";
        const RED: &str = "\x1b[31m";
        const YELLOW: &str = "\x1b[33m";

        let status = if r.success {
            format!("{GREEN}✓ Success")
        } else {
            format!("{RED}✗ Failed")
        };
        println!("    {status} ({}ms){RESET}", r.duration_ms);
        println!("{YELLOW}    Request Body (plaintext):{RESET}");
        println!("{DIM}      {}{RESET}", truncate(&r.request_body_plaintext, 200));
        println!("{YELLOW}    Response Body (decrypted):{RESET}");
        println!(
            "{DIM}      {}{RESET}",
            truncate(&r.response_body_decrypted, 200)
        );
        if !r.success {
            if let Some(ref e) = r.error {
                println!("{RED}    Error: {e}{RESET}");
            }
        }
        println!();
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.is_empty() {
            "(empty)".to_string()
        } else if s.len() > max {
            format!("{}...", &s[..max])
        } else {
            s.to_string()
        }
    }
}
