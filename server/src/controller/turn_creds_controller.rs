//! Mints short-lived TURN credentials for the web client.
//!
//! Implements coturn's `use-auth-secret` scheme: the username is
//! `<unix-expiry>:<arbitrary>` and the password is the base64 of
//! `HMAC-SHA1(secret, username)`. Both must match what coturn verifies,
//! which is why coturn must be started with `--static-auth-secret=<same>`.

use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

/// How long minted credentials remain valid.
const TTL_SECONDS: u64 = 3600;

#[derive(Serialize)]
pub struct TurnCredsResponse {
    /// TURN server URL list, e.g. `["turn:turn.example.org:3478"]`.
    pub urls: Vec<String>,
    /// `<expiry-unix>:<base-username>` — opaque to the client.
    pub username: String,
    /// Base64-encoded `HMAC-SHA1(secret, username)`.
    pub credential: String,
    /// Seconds until expiry; clients should refresh before this elapses.
    pub ttl: u64,
}

/// `GET /v1/turn-creds`
///
/// Returns 404 if TURN isn't configured on this deployment — the web client
/// then falls back to STUN-only, which is the same behavior as before TURN
/// was introduced.
pub async fn handler() -> Result<Json<TurnCredsResponse>, StatusCode> {
    let secret = std::env::var("TURN_AUTH_SECRET").map_err(|_| StatusCode::NOT_FOUND)?;
    let turn_url = std::env::var("TURN_URL").map_err(|_| StatusCode::NOT_FOUND)?;

    if secret.is_empty() || turn_url.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

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

    Ok(Json(TurnCredsResponse {
        urls: vec![turn_url],
        username,
        credential,
        ttl: TTL_SECONDS,
    }))
}
