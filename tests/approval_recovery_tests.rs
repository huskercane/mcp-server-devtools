//! Decision/application interruption boundaries, without pretending an intent is an effect.
use mcp_server_devtools::{
    approvals::ApprovalGate,
    policy::{Principal, PrincipalAuthority},
    ports::{
        Admission, ControlEvent, ControlEventKind, InMemoryAuditSink, MutationGate, MutationIntent,
        MutationKind, ProposalRegistry,
    },
};
use std::{fmt::Write as _, sync::Arc, time::Duration};

fn principal(subject: &str) -> Principal {
    Principal {
        tenant: "tenant".into(),
        subject: subject.into(),
        groups: vec![],
        scopes: vec!["mcp:admin".into()],
        authority: PrincipalAuthority::oidc("https://issuer.example"),
    }
}
fn gate(sink: Arc<InMemoryAuditSink>) -> ApprovalGate {
    ApprovalGate::new(sink, Duration::from_secs(1), Duration::from_hours(1))
}
async fn propose(gate: &ApprovalGate) -> String {
    match gate
        .admit(&MutationIntent {
            kind: MutationKind::PolicyInstall,
            principal: &principal("alice"),
            target: Some("2"),
            candidate: Some(b"version: 2\nrules: []\n"),
            signature: Some("signature"),
        })
        .await
    {
        Admission::Deferred { proposal } => proposal,
        other => panic!("{other:?}"),
    }
}
fn reopen(sink: &Arc<InMemoryAuditSink>) -> ApprovalGate {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-journal.jsonl");
    let mut records = String::new();
    for event in sink.events() {
        writeln!(records, "{event}").unwrap();
    }
    std::fs::write(&path, records).unwrap();
    ApprovalGate::open(
        sink.clone(),
        Duration::from_secs(1),
        Duration::from_hours(1),
        &path,
    )
    .unwrap()
}

#[tokio::test]
async fn approval_does_not_hand_out_a_second_application_before_completion() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let gate = gate(sink.clone());
    let id = propose(&gate).await;
    let bob = principal("bob");
    let (first, second) = tokio::join!(gate.approve(&id, &bob), gate.approve(&id, &bob));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(gate.approve(&id, &principal("alice")).await.is_err());
    assert_eq!(sink.events().len(), 2);
}

#[tokio::test]
async fn restart_does_not_infer_completion_from_an_intent_or_a_shared_version() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let gate = gate(sink.clone());
    let id = propose(&gate).await;
    gate.approve(&id, &principal("bob")).await.unwrap();
    let mut intent = ControlEvent::now(ControlEventKind::AdminMutation);
    intent.source = Some("policy/install".into());
    intent.version = Some("2".into());
    sink.append_control_now(&intent).unwrap();
    let recovered = reopen(&sink);
    assert_eq!(recovered.get("tenant", &id).unwrap().applied_seq, None);
    assert!(recovered.approve(&id, &principal("bob")).await.is_err());
}

#[tokio::test]
async fn completed_proposal_is_idempotent_and_does_not_complete_its_same_version_peer() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let gate = gate(sink.clone());
    let first = propose(&gate).await;
    let second = propose(&gate).await;
    for id in [&first, &second] {
        gate.approve(id, &principal("bob")).await.unwrap();
    }
    let mut intent = ControlEvent::now(ControlEventKind::AdminMutation);
    intent.source = Some("policy/install".into());
    intent.version = Some("2".into());
    let seq = sink.append_control_now(&intent).unwrap();
    gate.applied(&second, seq).await.unwrap();
    let recovered = reopen(&sink);
    assert!(
        recovered
            .approve(&second, &principal("bob"))
            .await
            .unwrap()
            .apply
            .is_none()
    );
    assert_eq!(
        recovered.get("tenant", &second).unwrap().applied_seq,
        Some(seq)
    );
    assert!(recovered.approve(&first, &principal("bob")).await.is_err());
    assert_eq!(recovered.get("tenant", &first).unwrap().applied_seq, None);
}

#[tokio::test]
async fn failed_decision_or_completion_append_cannot_enable_a_second_application() {
    let sink = Arc::new(InMemoryAuditSink::new());
    let gate = gate(sink.clone());
    let id = propose(&gate).await;
    sink.set_failing(true);
    assert!(gate.approve(&id, &principal("bob")).await.is_err());
    sink.set_failing(false);
    assert!(gate.approve(&id, &principal("bob")).await.is_err());
    let recovered = reopen(&sink);
    recovered.approve(&id, &principal("bob")).await.unwrap();
    sink.set_failing(true);
    assert!(recovered.applied(&id, 3).await.is_err());
    sink.set_failing(false);
    assert!(recovered.approve(&id, &principal("bob")).await.is_err());
    assert!(reopen(&sink).approve(&id, &principal("bob")).await.is_err());
}
