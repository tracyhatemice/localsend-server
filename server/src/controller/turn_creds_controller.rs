//! Returns the WebRTC ICE-server list for this deployment.
//!
//! The response shape mirrors the browser's `RTCIceServer[]` — the web
//! client can spread it directly into a `new RTCPeerConnection({ iceServers })`.
//!
//! ## Auth
//!
//! Requires a `peer_id` query param matching an active WebSocket session
//! (i.e. a peer that's currently registered in `AppState::tx_map`). This
//! prevents drive-by scraping of the endpoint — only clients with a live
//! signaling connection can mint TURN credentials.
//!
//! Returns:
//! - 400 if `peer_id` is missing or not a UUID.
//! - 403 if `peer_id` is well-formed but no active session has that ID.
//! - 404 if neither STUN_URL nor (TURN_URL+TURN_AUTH_SECRET) is configured.
//!
//! ## Configuration
//!
//! Two env vars drive the response body:
//!
//! - `STUN_URL`: if set, included as a STUN-only entry (no credentials).
//! - `TURN_URL` + `TURN_AUTH_SECRET`: if both set, included as a TURN entry
//!   with a freshly-minted HMAC-time-limited credential per coturn's
//!   `use-auth-secret` scheme. Username is `<unix-expiry>:<arbitrary>`,
//!   password is base64 of `HMAC-SHA1(secret, username)`. coturn validates
//!   this against `--static-auth-secret=<same secret>`.

use crate::config::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

#[derive(Deserialize)]
pub struct TurnCredsQuery {
    pub peer_id: String,
}

/// How long minted TURN credentials remain valid.
const TTL_SECONDS: u64 = 3600;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnCredsResponse {
    /// Ready to drop into `new RTCPeerConnection({ iceServers })`.
    pub ice_servers: Vec<IceServer>,
    /// Seconds until the TURN credentials expire (if any).
    /// Clients should refresh before this elapses.
    pub ttl: u64,
}

/// `GET /v1/turn-creds?peer_id=<uuid>`
pub async fn handler(
    State(state): State<AppState>,
    Query(query): Query<TurnCredsQuery>,
) -> Result<Json<TurnCredsResponse>, StatusCode> {
    // Auth: caller must have an active WebSocket session.
    let peer_id = Uuid::parse_str(&query.peer_id).map_err(|_| StatusCode::BAD_REQUEST)?;
    let active = {
        let tx_map = state.tx_map.lock().await;
        tx_map.values().any(|inner| inner.contains_key(&peer_id))
    };
    if !active {
        return Err(StatusCode::FORBIDDEN);
    }

    let stun_url = std::env::var("STUN_URL").unwrap_or_default();
    let turn_url = std::env::var("TURN_URL").unwrap_or_default();
    let secret = std::env::var("TURN_AUTH_SECRET").unwrap_or_default();

    let mut ice_servers = Vec::new();

    if !stun_url.is_empty() {
        ice_servers.push(IceServer {
            urls: vec![stun_url],
            username: None,
            credential: None,
        });
    }

    if !turn_url.is_empty() && !secret.is_empty() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .as_secs();
        let expiry = now + TTL_SECONDS;
        let username = format!("{expiry}:localsend");

        let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        mac.update(username.as_bytes());
        let credential = STANDARD.encode(mac.finalize().into_bytes());

        ice_servers.push(IceServer {
            urls: vec![turn_url],
            username: Some(username),
            credential: Some(credential),
        });
    }

    if ice_servers.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(TurnCredsResponse {
        ice_servers,
        ttl: TTL_SECONDS,
    }))
}
