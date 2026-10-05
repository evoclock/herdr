//! Private, opt-in experiment. Admission is internal, never §3.1 delivery.
//! App admission linearizes at the final validation event. Later pane moves are
//! ordered after that decision; receiver admission separately pins live Pi/modal.
use super::{
    super::App,
    responses::{encode_error, encode_success},
};
use crate::{
    api::schema::{AgentNudgeOutcome, AgentNudgeParams, AgentStatus, ResponseResult},
    events::AppEvent,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
pub(crate) const CAPABILITY: &str = "extension-owned-detached-confirm-tui-v2";

#[derive(Default)]
pub(crate) struct ProofState {
    pub root: Option<PathBuf>,
    gates: HashMap<String, Arc<AtomicBool>>,
}
impl ProofState {
    pub fn from_env() -> Self {
        Self {
            root: if std::env::var("HERDR_NUDGE_PROOF").as_deref() == Ok("1") {
                std::env::var_os("HERDR_NUDGE_PROOF_ROOT").map(PathBuf::from)
            } else {
                None
            },
            gates: HashMap::new(),
        }
    }
    pub fn acquire(&mut self, terminal: &str) -> Result<Admission, &'static str> {
        let gate = self.gates.entry(terminal.into()).or_default().clone();
        if gate
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("pane_admission_busy");
        }
        Ok(Admission(gate))
    }
}
pub(crate) struct Admission(Arc<AtomicBool>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn verdict(id: &str, p: &AgentNudgeParams, outcome: AgentNudgeOutcome, code: &str) -> String {
    encode_success(
        id.into(),
        ResponseResult::AgentNudged {
            nudge_id: p.nudge_id.clone(),
            target_instance: None,
            outcome,
            code: code.into(),
        },
    )
}
impl App {
    pub(super) fn proof_snapshot_matches(&self, p: &AgentNudgeParams) -> bool {
        let Ok(r) = self.resolve_terminal_target(&p.target) else {
            return false;
        };
        let Some(a) = self.agent_info(r.ws_idx, r.pane_id) else {
            return false;
        };
        let e = &p.expected_instance;
        if a.terminal_id != e.terminal_id
            || a.workspace_id != e.workspace_id
            || a.tab_id != e.tab_id
            || a.pane_id != e.pane_id
            || a.revision != e.revision
            || a.state_change_seq != e.state_change_seq
            || a.launch_pending
            || !a.interactive_ready
            || a.agent.as_deref() != Some("pi")
            || !matches!(
                a.agent_status,
                AgentStatus::Idle | AgentStatus::Working | AgentStatus::Blocked
            )
        {
            return false;
        }
        let Some(pi) = &p.expected_pi else {
            return false;
        };
        let Some(runtime) = self.lookup_runtime_sender(r.ws_idx, r.pane_id) else {
            return false;
        };
        super::super::agents::runtime_hosts_agent(runtime, crate::detect::Agent::Pi)
            && runtime
                .child_pid()
                .and_then(crate::detect::foreground_job)
                .is_some_and(|j| j.processes.iter().any(|x| x.pid == pi.pid))
    }
    pub(super) fn start_nudge_proof(
        &mut self,
        id: String,
        p: AgentNudgeParams,
        reply: mpsc::Sender<String>,
    ) {
        let refuse = |code| {
            let _ = reply.send(verdict(
                &id,
                &p,
                AgentNudgeOutcome::RejectedBeforeDelivery,
                code,
            ));
        };
        let Some(root) = self.nudge_proof.root.clone() else {
            refuse("prototype_disabled");
            return;
        };
        if !crate::api::schema::is_canonical_nudge_id(&p.nudge_id)
            || p.text.trim().is_empty()
            || p.text.len() > 2048
            || !(1..=5000).contains(&p.timeout_ms)
        {
            refuse("invalid_nudge_request");
            return;
        }
        let Some(pi) = &p.expected_pi else {
            refuse("pi_identity_required");
            return;
        };
        if pi.pid == 0
            || pi.session_id.len() < 8
            || pi.session_id.len() > 128
            || pi.boot_nonce.len() != 24
            || !pi
                .boot_nonce
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || pi.modal_ticket.len() < 8
            || pi.modal_ticket.len() > 128
        {
            refuse("invalid_pi_identity");
            return;
        }
        if !self.proof_snapshot_matches(&p) {
            refuse("target_instance_changed");
            return;
        }
        // Both ordinary queued submissions and proofs use this SAME terminal gate.
        // No waiting on the app thread: competing requests explicitly refuse.
        self.nudge_proof
            .gates
            .retain(|id, _| self.state.terminals.contains_key(id.as_str()));
        let admission = match self.nudge_proof.acquire(&p.expected_instance.terminal_id) {
            Ok(g) => g,
            Err(c) => {
                refuse(c);
                return;
            }
        };
        let events = self.event_tx.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(u64::from(p.timeout_ms));
            let result = execute(&root, &p, deadline, || {
                let (tx, rx) = mpsc::channel();
                let event = AppEvent::NudgeProofValidate {
                    params: Box::new(p.clone()),
                    reply: tx,
                };
                events.try_send(event).map_err(|_| "admission_cancelled")?;
                rx.recv_timeout(remaining(deadline)?)
                    .map_err(|_| "admission_cancelled")
                    .and_then(|yes| {
                        if yes {
                            Ok(())
                        } else {
                            Err("target_instance_changed")
                        }
                    })
            });
            let (outcome, code) = match result {
                Ok(duplicate) => (
                    AgentNudgeOutcome::Unknown,
                    if duplicate {
                        "accepted_durable_duplicate_internal_not_delivered"
                    } else {
                        "accepted_durable_internal_not_delivered"
                    },
                ),
                Err((sent, code)) => (
                    if sent {
                        AgentNudgeOutcome::Unknown
                    } else {
                        AgentNudgeOutcome::RejectedBeforeDelivery
                    },
                    code,
                ),
            };
            drop(admission); // deadline/late/lost ack cannot hold another pane hostage
            let _ = reply.send(verdict(&id, &p, outcome, code));
        });
    }
    pub(super) fn handle_agent_nudge_proof(&self, id: String, _p: AgentNudgeParams) -> String {
        encode_error(
            id,
            "deferred_request_required",
            "private proof is handled off the app loop",
        )
    }
}
fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or("proof_timeout")
}
fn exchange(port: u16, request: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let encoded = serde_json::to_vec(request).map_err(|_| "invalid_request")?;
    let mut socket = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        remaining(deadline)?,
    )
    .map_err(|_| "extension_unavailable")?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "transport_unavailable")?;
    let mut frame = encoded.clone();
    frame.push(b'\n');
    let mut written = 0;
    while written < frame.len() {
        remaining(deadline)?;
        match socket.write(&frame[written..]) {
            Ok(0) => return Err("ack_write_failed"),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(1)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("ack_write_failed"),
        }
    }
    let _ = socket.shutdown(Shutdown::Write);
    let mut bytes = Vec::new();
    let mut buf = [0; 512];
    loop {
        remaining(deadline)?;
        let n = match socket.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(1)));
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("ack_read_failed"),
        };
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
        if bytes.len() > 4096 {
            return Err("ack_frame_too_large");
        }
    }
    let ack: Value = serde_json::from_slice(&bytes).map_err(|_| "malformed_ack")?;
    let digest = format!("{:x}", Sha256::digest(&encoded));
    if ack["requestId"] != request["requestId"]
        || ack["requestDigest"] != digest
        || ack["expected"] != request["expected"]
        || ack["expectedInstance"] != request["expectedInstance"]
        || ack["modalTicket"] != request["modalTicket"]
    {
        return Err("uncorrelated_ack");
    }
    Ok(ack)
}
fn execute(
    root: &std::path::Path,
    p: &AgentNudgeParams,
    deadline: Instant,
    validate: impl FnOnce() -> Result<(), &'static str>,
) -> Result<bool, (bool, &'static str)> {
    let mut discovery =
        crate::platform::pinned_proof_file::PinnedProofFile::open(root).map_err(|c| (false, c))?;
    let bytes = discovery.read().map_err(|c| (false, c))?;
    let sidecar: Value =
        serde_json::from_slice(&bytes).map_err(|_| (false, "invalid_extension_identity"))?;
    let pi = p
        .expected_pi
        .as_ref()
        .ok_or((false, "pi_identity_required"))?;
    if sidecar["capability"] != CAPABILITY
        || sidecar["paneId"] != p.expected_instance.pane_id
        || sidecar["workspaceId"] != p.expected_instance.workspace_id
        || sidecar["tabId"] != p.expected_instance.tab_id
        || sidecar["pid"] != pi.pid
        || sidecar["sessionId"] != pi.session_id
        || sidecar["bootNonce"] != pi.boot_nonce
        || sidecar["modalTicket"] != pi.modal_ticket
    {
        return Err((false, "pi_identity_changed"));
    }
    let port = sidecar["port"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or((false, "invalid_extension_identity"))?;
    let instance =
        serde_json::to_value(&p.expected_instance).map_err(|_| (false, "invalid_request"))?;
    let mut request = json!({"op":"inspect-bound-modal", "requestId":format!("{}-{}", std::process::id(), NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)), "expected":{"pid":pi.pid,"sessionId":pi.session_id,"bootNonce":pi.boot_nonce}, "expectedInstance":instance, "modalTicket":pi.modal_ticket, "capability":CAPABILITY});
    let preflight = exchange(port, &request, deadline).map_err(|c| (false, c))?;
    if preflight["ok"] != true || preflight["modalState"] != "pending" {
        return Err((false, "controlled_modal_unavailable"));
    }
    // Final app-loop linearization, no filesystem/socket I/O there.
    validate().map_err(|c| (false, c))?;
    // Re-read the pinned fd after preflight to reject discovery replacement.
    // Same-UID malicious code remains outside this trust model.
    if discovery.read().map_err(|c| (false, c))? != bytes {
        return Err((false, "extension_identity_changed"));
    }
    request["op"] = json!("accept-bound");
    request["requestId"] = json!(format!(
        "{}-{}",
        std::process::id(),
        NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
    ));
    request["message"] = json!({"schema":"agentic-driver.pi-modal-inbox.experimental.v1","nudgeId":p.nudge_id,"text":p.text,"expected":request["expected"]});
    // From here uncertainty ALWAYS remains Unknown, including connect errors.
    // No retry; status/query is a separate read-only owner operation.
    let ack = exchange(port, &request, deadline).map_err(|c| (true, c))?;
    if ack["ok"] == true
        && ack["state"] == "accepted-durable"
        && ack["nudgeId"] == p.nudge_id
        && ack["duplicate"].is_boolean()
        && ack["seq"].as_u64().is_some_and(|s| s > 0)
    {
        return Ok(ack["duplicate"] == true);
    }
    // Even a correlated negative receiver ACK is only internal evidence.
    // After an accept send attempt, the public outcome never claims rejection.
    if ack["ok"] == false
        && ack["admitted"] == false
        && matches!(
            ack["code"].as_str(),
            Some(
                "controlled-modal-unavailable"
                    | "identity-mismatch"
                    | "instance-mismatch"
                    | "stale-modal"
                    | "invalid-request"
                    | "conflicting-id"
                    | "capacity"
            )
        )
    {
        return Err((true, "extension_refused_internal_not_delivered"));
    }
    Err((true, "internal_ack_unknown"))
}
static NEXT_REQUEST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn admission_is_per_terminal_and_retained_until_completion() {
        let mut state = ProofState::default();
        let prompt = state.acquire("a").unwrap();
        assert!(state.acquire("a").is_err());
        let other = state.acquire("b").unwrap();
        assert!(state.acquire("a").is_err());
        drop(prompt);
        assert!(state.acquire("a").is_ok());
        drop(other);
    }
    fn fixture() -> (PathBuf, AgentNudgeParams) {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::current_dir()
            .unwrap()
            .join("scratch")
            .join(format!(
                "protocol-{}-{}",
                std::process::id(),
                NEXT_REQUEST.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = AgentNudgeParams {
            target: "w1:p1".into(),
            expected_instance: crate::api::schema::AgentNudgeTargetIdentity {
                terminal_id: "term-1".into(),
                workspace_id: "w1".into(),
                tab_id: "w1:t1".into(),
                pane_id: "w1:p1".into(),
                revision: 1,
                state_change_seq: 2,
            },
            expected_pi: Some(crate::api::schema::AgentNudgePiIdentity {
                pid: 123,
                session_id: "session-123".into(),
                boot_nonce: "a".repeat(24),
                modal_ticket: "ticket-123".into(),
            }),
            nudge_id: "12345678-1234-4123-8123-000000000778".into(),
            text: "Enter\nEscape\ryes\u{1b}[A".into(),
            timeout_ms: 500,
        };
        (root, p)
    }
    fn sidecar(root: &std::path::Path, p: &AgentNudgeParams, port: u16) {
        use std::os::unix::fs::PermissionsExt;
        let pi = p.expected_pi.as_ref().unwrap();
        let f = root.join("proof-identity.json");
        std::fs::write(&f, serde_json::to_vec(&json!({"port":port,"pid":pi.pid,"sessionId":pi.session_id,"bootNonce":pi.boot_nonce,"modalTicket":pi.modal_ticket,"paneId":p.expected_instance.pane_id,"workspaceId":p.expected_instance.workspace_id,"tabId":p.expected_instance.tab_id,"capability":CAPABILITY})).unwrap()).unwrap();
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn test_accept(listener: &std::net::TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    return socket;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < end, "mock peer accept deadline");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("mock peer accept: {e}"),
            }
        }
    }
    fn peer(mode: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = std::thread::spawn(move || {
            for i in 0..2 {
                let mut socket = test_accept(&listener);
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).unwrap();
                let req: Value = serde_json::from_slice(&bytes).unwrap();
                if i == 1 && mode == "lost" {
                    continue;
                }
                let mut ack = json!({"ok":true,"requestId":req["requestId"],"requestDigest":format!("{:x}",Sha256::digest(bytes.strip_suffix(b"\n").unwrap())),"expected":req["expected"],"expectedInstance":req["expectedInstance"],"modalTicket":req["modalTicket"],"modalState":"pending","state":"accepted-durable","nudgeId":req["message"]["nudgeId"],"seq":1,"duplicate":mode == "duplicate"});
                if i == 1 {
                    if mode == "wrong-id" {
                        ack["requestId"] = json!("other-request");
                    }
                    if mode == "wrong-peer" {
                        ack["expected"]["bootNonce"] = json!("different");
                    }
                    if mode == "late" {
                        std::thread::sleep(Duration::from_millis(120));
                    }
                    if mode == "malformed" {
                        let _ = socket.write_all(b"not-json\n");
                        continue;
                    }
                    if mode == "refused" {
                        ack["ok"] = json!(false);
                        ack["admitted"] = json!(false);
                        ack["code"] = json!("controlled-modal-unavailable");
                    }
                    if mode == "uncertain" {
                        ack["ok"] = json!(false);
                        ack["code"] = json!("unknown-after-attempt");
                    }
                }
                let _ = socket.write_all(&serde_json::to_vec(&ack).unwrap());
            }
        });
        (port, task)
    }
    fn scenario(mode: &'static str) -> Result<bool, (bool, &'static str)> {
        let (root, p) = fixture();
        let (port, task) = peer(mode);
        sidecar(&root, &p, port);
        let result = execute(
            &root,
            &p,
            Instant::now() + Duration::from_millis(if mode == "late" { 50 } else { 500 }),
            || Ok(()),
        );
        task.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        result
    }
    #[test]
    fn proof_protocol_correlates_fresh_and_exact_duplicate_without_retry() {
        assert_eq!(scenario("fresh"), Ok(false));
        assert_eq!(scenario("duplicate"), Ok(true));
    }
    #[test]
    fn proof_protocol_lost_malformed_late_and_uncertain_ack_stay_unknown() {
        for mode in ["lost", "malformed", "late", "uncertain", "refused"] {
            assert!(matches!(scenario(mode), Err((true, _))), "{mode}");
        }
    }
    #[test]
    fn proof_protocol_mismatched_peer_or_request_never_acknowledges_admission() {
        assert_eq!(scenario("wrong-id"), Err((true, "uncorrelated_ack")));
        assert_eq!(scenario("wrong-peer"), Err((true, "uncorrelated_ack")));
    }
    #[test]
    fn sidecar_pane_identity_mismatch_refuses_without_connect() {
        let (root, p) = fixture();
        sidecar(&root, &p, 1);
        let mut changed = p.clone();
        changed.expected_instance.pane_id = "w1:p2".into();
        assert_eq!(
            execute(
                &root,
                &changed,
                Instant::now() + Duration::from_millis(100),
                || Ok(())
            ),
            Err((false, "pi_identity_changed"))
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn final_revalidation_cancels_before_any_accept_payload() {
        let (root, p) = fixture();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        sidecar(&root, &p, listener.local_addr().unwrap().port());
        let task = std::thread::spawn(move || {
            let mut c = test_accept(&listener);
            let mut b = Vec::new();
            c.read_to_end(&mut b).unwrap();
            let r: Value = serde_json::from_slice(&b).unwrap();
            assert_eq!(r["op"], "inspect-bound-modal");
            let ack = json!({"ok":true,"modalState":"pending","requestId":r["requestId"],"requestDigest":format!("{:x}",Sha256::digest(b.strip_suffix(b"\n").unwrap())),"expected":r["expected"],"expectedInstance":r["expectedInstance"],"modalTicket":r["modalTicket"]});
            c.write_all(&serde_json::to_vec(&ack).unwrap()).unwrap();
        });
        assert_eq!(
            execute(
                &root,
                &p,
                Instant::now() + Duration::from_millis(500),
                || Err("target_instance_changed")
            ),
            Err((false, "target_instance_changed"))
        );
        task.join().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn timeout_is_a_total_deadline_not_a_fresh_timeout_per_read() {
        assert_eq!(
            remaining(Instant::now() - Duration::from_millis(1)).unwrap_err(),
            "proof_timeout"
        );
    }
}
