//! Axum router: /v1/health, /v1/enroll, /v1/sessions/{id}/parts/{part}.

#![allow(dead_code)]

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::chain::{self, ChainLock, SenderChain};
use crate::config::Config;
use crate::enroll::{self, EnrollmentDir, ValidateResult};
use crate::storage::{self, SenderDirs};
use crate::tls::PinnedCerts;
use crate::verify;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub pinned: PinnedCerts,
    pub enroll_secret: Arc<Vec<u8>>,
    pub collector_cert_pem: Arc<String>,
    pub collector_fingerprint_hex: Arc<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/enroll", post(enroll_handler))
        .route(
            "/v1/sessions/{session_id}/parts/{part}",
            post(push_handler),
        )
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

// --- Enrollment ---

#[derive(Deserialize)]
struct EnrollBody {
    sender_name: String,
    token: String,
    tls_cert_pem: String,
    signing_pub_hex: String,
}

#[derive(Serialize)]
struct EnrollResponse {
    collector_tls_cert_pem: String,
    collector_fingerprint_sha256: String,
}

async fn enroll_handler(
    State(state): State<AppState>,
    Json(body): Json<EnrollBody>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    // Run blocking filesystem operations in a spawn_blocking task.
    let state2 = state.clone();
    tokio::task::spawn_blocking(move || enroll_blocking(state2, body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn enroll_blocking(
    state: AppState,
    body: EnrollBody,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    let edir = EnrollmentDir::under(&state.cfg.storage.dir);

    // Validate the token.
    let validated = enroll::validate_token(&state.enroll_secret, &edir, &body.token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match validated {
        ValidateResult::Ok { sender_name } => {
            if sender_name != body.sender_name {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "token does not belong to this sender_name".into(),
                ));
            }
        }
        ValidateResult::Expired => {
            return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
        }
        ValidateResult::AlreadyBurned => {
            return Err((StatusCode::UNAUTHORIZED, "token already used".into()));
        }
        ValidateResult::NotPending | ValidateResult::BadMac | ValidateResult::Malformed => {
            return Err((StatusCode::UNAUTHORIZED, "invalid token".into()));
        }
    }

    // Parse the sender's TLS cert.
    let tls_cert_ders: Vec<_> = rustls_pemfile::certs(&mut body.tls_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cert pem: {e}")))?;
    if tls_cert_ders.len() != 1 {
        return Err((StatusCode::BAD_REQUEST, "expected exactly one cert".into()));
    }
    let cert_der = &tls_cert_ders[0];

    // Parse signing pubkey.
    let signing_pub = hex::decode(&body.signing_pub_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("signing pub hex: {e}")))?;
    if signing_pub.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "signing pub must be 32 bytes".into(),
        ));
    }

    // Create sender dir (fails if already enrolled with different cert).
    let sender = SenderDirs::under(&state.cfg.storage.dir, &body.sender_name)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if sender.root.exists() {
        return Err((StatusCode::CONFLICT, "sender already enrolled".into()));
    }
    sender
        .ensure_created()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Write sender state.
    storage::put_atomic(&sender.cert_pem, body.tls_cert_pem.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fp_hex = crate::tls::fingerprint_hex(cert_der.as_ref());
    storage::put_atomic(&sender.cert_fingerprint, fp_hex.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    storage::put_atomic(&sender.signing_pub, &signing_pub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Burn the token.
    let mut h = Sha256::new();
    h.update(body.token.as_bytes());
    let token_hash = hex::encode(h.finalize());
    enroll::burn(&edir, &token_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Add to in-memory pinned set so the TLS verifier trusts this cert.
    state.pinned.add_der(cert_der.as_ref());

    Ok(Json(EnrollResponse {
        collector_tls_cert_pem: state.collector_cert_pem.to_string(),
        collector_fingerprint_sha256: state.collector_fingerprint_hex.to_string(),
    }))
}

// --- Push ---

async fn push_handler(
    State(state): State<AppState>,
    AxumPath((session_id, part)): AxumPath<(String, u32)>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Run blocking filesystem + crypto ops in spawn_blocking.
    tokio::task::spawn_blocking(move || push_blocking(state, session_id, part, body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn push_blocking(
    state: AppState,
    session_id: String,
    part: u32,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Parse the framed body: u32 BE manifest_len | manifest_json | recording_bytes
    if body.len() < 4 {
        return Err((StatusCode::BAD_REQUEST, "body too short".into()));
    }
    let manifest_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    if manifest_len > 65536 || 4 + manifest_len > body.len() {
        return Err((StatusCode::BAD_REQUEST, "invalid manifest length".into()));
    }
    let manifest_bytes = &body[4..4 + manifest_len];
    let recording_bytes = &body[4 + manifest_len..];

    // Parse manifest.
    let manifest = verify::parse_manifest(manifest_bytes)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    // Validate URL matches manifest.
    if manifest.session_id != session_id || manifest.part != part {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "session/part mismatch with URL".into(),
        ));
    }

    // Find the sender whose signing.pub verifies this manifest.
    let sender_name = find_sender_for_manifest(&state.cfg.storage.dir, &manifest)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    // Load sender state.
    let sender = SenderDirs::under(&state.cfg.storage.dir, &sender_name)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Verify manifest signature.
    let signing_pub_bytes = std::fs::read(&sender.signing_pub)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("read signing.pub: {e}")))?;
    if signing_pub_bytes.len() != 32 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "bad signing.pub on disk".into(),
        ));
    }
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&signing_pub_bytes);
    manifest
        .verify(&pub_arr)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;

    // Verify recording SHA-256.
    let mut h = Sha256::new();
    h.update(recording_bytes);
    let computed_hash = hex::encode(h.finalize());
    if computed_hash != manifest.recording_sha256 {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "recording sha256 mismatch".into(),
        ));
    }

    // Per-sender chain lock.
    let chain_obj = SenderChain::under(&sender.root);
    let _lock = ChainLock::acquire(&chain_obj)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let current_head = chain::read_head(&chain_obj)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Compute recording + sidecar paths.
    let (rec_path, sidecar_path) =
        storage::recording_paths(&sender, &manifest.user, &manifest.session_id, manifest.part)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Idempotency: if recording already stored with same hash, return 409 success.
    if rec_path.exists() {
        let existing_hash = sha256_file_hex(&rec_path);
        if existing_hash == manifest.recording_sha256 {
            return Ok(Json(serde_json::json!({
                "stored": true,
                "head_hash": current_head,
                "idempotent": true
            })));
        }
        return Err((
            StatusCode::CONFLICT,
            "different recording already stored".into(),
        ));
    }

    // Strict chain: prev must match current head.
    if manifest.prev_manifest_hash != current_head {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            format!(
                "chain gap: collector head {} != manifest prev {}",
                current_head, manifest.prev_manifest_hash
            ),
        ));
    }

    // Write recording + sidecar atomically.
    storage::put_atomic(&rec_path, recording_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    storage::put_atomic(&sidecar_path, manifest_bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Advance chain.
    chain::strict_advance(&chain_obj, &current_head, &manifest.this_manifest_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    chain::append_log(
        &chain_obj,
        &format!("{now}"),
        &manifest.user,
        &manifest.session_id,
        manifest.part,
        &manifest.this_manifest_hash,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "stored": true,
        "head_hash": manifest.this_manifest_hash,
    })))
}

/// Walk senders/*/signing.pub and find which one verifies this manifest.
/// O(senders) per request — acceptable for small fleets. Task 14
/// replaces this with peer-cert identification from the TLS layer.
fn find_sender_for_manifest(
    storage_dir: &std::path::Path,
    manifest: &verify::Manifest,
) -> Result<String, String> {
    let senders_dir = storage_dir.join("senders");
    let read = std::fs::read_dir(&senders_dir).map_err(|e| format!("read senders: {e}"))?;
    for entry in read {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let pub_path = entry.path().join("signing.pub");
        let bytes = match std::fs::read(&pub_path) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        if manifest.verify(&arr).is_ok() {
            return Ok(name);
        }
    }
    Err("no enrolled sender verifies this manifest".into())
}

fn sha256_file_hex(path: &std::path::Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}
