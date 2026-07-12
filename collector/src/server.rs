//! Axum router: /v1/health, /v1/enroll, /v1/sessions/{id}/parts/{part}.

#![allow(dead_code)]

use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
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

/// SHA-256 hex fingerprint of the mTLS peer (client) certificate for the
/// current connection, or `None` if no client cert was presented. Injected as a
/// per-connection request extension by the TLS accept loop.
#[derive(Clone, Default)]
pub struct PeerFingerprint(pub Option<String>);

pub fn router(state: AppState) -> Router {
    // Read limits before `state` is moved into the router.
    let max_body = state.cfg.storage.max_upload_bytes as usize;
    let timeout = std::time::Duration::from_secs(state.cfg.listen.request_timeout_seconds);
    let concurrency = state.cfg.listen.max_concurrent_requests;

    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/enroll", post(enroll_handler))
        .route(
            "/v1/sessions/{session_id}/parts/{part}",
            post(push_handler),
        )
        // Bound resource use: cap the body (the configured max_upload_bytes is
        // now authoritative, replacing axum's silent 2 MiB default), drop
        // slow/stuck requests, and limit in-flight concurrency.
        .layer(axum::extract::DefaultBodyLimit::max(max_body))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(tower::limit::ConcurrencyLimitLayer::new(concurrency))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

// --- Enrollment ---

#[derive(Deserialize, Clone)]
struct EnrollBody {
    sender_name: String,
    token: String,
    tls_cert_pem: String,
    signing_pub_hex: String,
}

#[derive(Serialize, Debug)]
struct EnrollResponse {
    collector_tls_cert_pem: String,
    collector_fingerprint_sha256: String,
}

async fn enroll_handler(
    State(state): State<AppState>,
    Extension(peer): Extension<PeerFingerprint>,
    Json(body): Json<EnrollBody>,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    // Run blocking filesystem operations in a spawn_blocking task.
    let state2 = state.clone();
    tokio::task::spawn_blocking(move || enroll_blocking(state2, peer.0, body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn enroll_blocking(
    state: AppState,
    peer_fingerprint: Option<String>,
    body: EnrollBody,
) -> Result<Json<EnrollResponse>, (StatusCode, String)> {
    let edir = EnrollmentDir::under(&state.cfg.storage.dir);

    // Serialize validate -> burn -> write under an exclusive lock so a
    // single-use token cannot be consumed by two concurrent requests (both
    // would otherwise pass validation before either burns).
    let _lock = edir
        .lock_exclusive()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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

    // Proof of possession: the enrolling cert must equal the cert presented in
    // the TLS handshake, which proves the client holds its private key. This
    // rejects registering a cert the client does not control.
    let cert_fp = crate::tls::fingerprint_hex(cert_der.as_ref());
    if peer_fingerprint.as_deref() != Some(cert_fp.as_str()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "enrollment cert must be presented as the TLS client certificate".into(),
        ));
    }

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

    // Burn the token BEFORE writing any sender state: once all checks pass we
    // commit the single use atomically, so a crash mid-write cannot leave a
    // reusable token. (Conflicts above return without burning, so a wasted
    // enrollment attempt does not consume the token.)
    let mut h = Sha256::new();
    h.update(body.token.as_bytes());
    let token_hash = hex::encode(h.finalize());
    enroll::burn(&edir, &token_hash)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
    Extension(peer): Extension<PeerFingerprint>,
    AxumPath((session_id, part)): AxumPath<(String, u32)>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Run blocking filesystem + crypto ops in spawn_blocking.
    tokio::task::spawn_blocking(move || push_blocking(state, peer.0, session_id, part, body))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn push_blocking(
    state: AppState,
    peer_fingerprint: Option<String>,
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

    // Identify the sender from the authenticated mTLS client cert (already
    // verified as pinned at the TLS layer). O(senders) directory reads with no
    // crypto — this replaces trial-verifying the manifest against every
    // enrolled key, which was an unauthenticated CPU-amplification DoS. The
    // manifest must then still verify against THIS sender's signing key below,
    // binding the transport identity to the signing identity.
    let peer_fingerprint = peer_fingerprint
        .ok_or((StatusCode::UNAUTHORIZED, "client certificate required".into()))?;
    let sender_name = find_sender_by_fingerprint(&state.cfg.storage.dir, &peer_fingerprint)
        .ok_or((StatusCode::UNAUTHORIZED, "client cert not enrolled".into()))?;

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

/// Resolve the enrolled sender whose pinned cert fingerprint equals `fp_hex`.
/// Directory reads only, no crypto — the mTLS layer already authenticated the
/// cert, so this is a plain identity lookup, not an attacker-triggerable
/// signature loop.
fn find_sender_by_fingerprint(storage_dir: &std::path::Path, fp_hex: &str) -> Option<String> {
    let senders_dir = storage_dir.join("senders");
    for entry in std::fs::read_dir(&senders_dir).ok()?.flatten() {
        let fp_path = entry.path().join("cert.fingerprint");
        if let Ok(stored) = std::fs::read_to_string(&fp_path)
            && stored.trim() == fp_hex
        {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

fn sha256_file_hex(path: &std::path::Path) -> String {
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn state_with(cfg: Config, secret: Vec<u8>) -> AppState {
        AppState {
            cfg: Arc::new(cfg),
            pinned: PinnedCerts::new(),
            enroll_secret: Arc::new(secret),
            collector_cert_pem: Arc::new("collector-cert".into()),
            collector_fingerprint_hex: Arc::new("fp".into()),
        }
    }

    #[test]
    fn enroll_token_is_single_use() {
        let dir = tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.storage.dir = dir.path().to_path_buf();
        let secret = vec![7u8; 32];

        let edir = EnrollmentDir::under(&cfg.storage.dir);
        edir.ensure_created().unwrap();
        let gt = enroll::generate_token(&secret, "sender-a", 3600).unwrap();
        enroll::write_pending(&edir, &gt.token_hash_hex, "sender-a", gt.expires_at).unwrap();

        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        crate::tls::generate_self_signed(&cert, &key, "sender-a").unwrap();
        let cert_pem = std::fs::read_to_string(&cert).unwrap();
        // The cert the sender presents in the TLS handshake == the one it enrolls.
        let cert_fp = crate::tls::fingerprint_hex(&crate::tls::read_cert_der(&cert).unwrap());

        let state = state_with(cfg, secret);
        let body = || EnrollBody {
            sender_name: "sender-a".into(),
            token: gt.token.clone(),
            tls_cert_pem: cert_pem.clone(),
            signing_pub_hex: hex::encode([9u8; 32]),
        };

        // First enroll succeeds; the token is burned before any state write.
        assert!(enroll_blocking(state.clone(), Some(cert_fp.clone()), body()).is_ok());
        // The same token cannot be reused.
        let (code, _) = enroll_blocking(state.clone(), Some(cert_fp), body()).unwrap_err();
        assert_eq!(code, StatusCode::UNAUTHORIZED, "reused token must be rejected");
    }

    #[test]
    fn enroll_requires_cert_presented_in_handshake() {
        let dir = tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.storage.dir = dir.path().to_path_buf();
        let secret = vec![7u8; 32];

        let edir = EnrollmentDir::under(&cfg.storage.dir);
        edir.ensure_created().unwrap();
        let gt = enroll::generate_token(&secret, "sender-a", 3600).unwrap();
        enroll::write_pending(&edir, &gt.token_hash_hex, "sender-a", gt.expires_at).unwrap();

        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        crate::tls::generate_self_signed(&cert, &key, "sender-a").unwrap();
        let cert_pem = std::fs::read_to_string(&cert).unwrap();

        let state = state_with(cfg, secret);
        let body = EnrollBody {
            sender_name: "sender-a".into(),
            token: gt.token.clone(),
            tls_cert_pem: cert_pem,
            signing_pub_hex: hex::encode([9u8; 32]),
        };

        // No client cert presented, or a cert that doesn't match the enrolling
        // cert -> rejected (no proof the enroller holds the key).
        let (code, _) = enroll_blocking(state.clone(), None, body.clone()).unwrap_err();
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let (code, _) =
            enroll_blocking(state, Some("deadbeef".into()), body).unwrap_err();
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn find_sender_by_fingerprint_matches_enrolled_only() {
        let dir = tempdir().unwrap();
        let alice = dir.path().join("senders/alice");
        std::fs::create_dir_all(&alice).unwrap();
        std::fs::write(alice.join("cert.fingerprint"), "abc123\n").unwrap();
        assert_eq!(
            find_sender_by_fingerprint(dir.path(), "abc123").as_deref(),
            Some("alice")
        );
        assert_eq!(find_sender_by_fingerprint(dir.path(), "deadbeef"), None);
    }

    #[tokio::test]
    async fn body_over_configured_limit_is_rejected() {
        use tower::ServiceExt;
        let dir = tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.storage.dir = dir.path().to_path_buf();
        cfg.storage.max_upload_bytes = 50; // authoritative, not axum's 2 MiB default
        // The TLS loop injects the peer fingerprint per connection; supply one
        // here so the request reaches the body-limit layer.
        let app = router(state_with(cfg, vec![0u8; 32]))
            .layer(Extension(PeerFingerprint(Some("testfp".into()))));

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sessions/s/parts/0")
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(vec![0u8; 100]))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
