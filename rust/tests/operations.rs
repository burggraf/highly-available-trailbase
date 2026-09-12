use hat::{
    config::Config,
    journal::Journal,
    node::{Admission, ChildState, NodeRole, NodeRuntime, NodeState},
    operations::{
        FailoverError, FaultPoint, FenceEvidence, LossBound, LossReport, ManualFailover,
        PlannedSwitchover, ReconcileEvidence, RejoinSpec, SwitchoverError, SwitchoverSpec,
    },
    restore::RestoreRequest,
    routing::{Route, RouteTable},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const CLUSTER: &str = "11111111-1111-4111-8111-111111111111";
const OLD_INCARNATION: &str = "22222222-2222-4222-8222-222222222222";
const NEW_INCARNATION: &str = "33333333-3333-4333-8333-333333333333";
const ACTION: &str = "44444444-4444-4444-8444-444444444444";
const EVIDENCE: &str = "55555555-5555-4555-8555-555555555555";
const RELEASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn config() -> Config {
    Config::from_json(
        r#"{"schema_version":1,"cluster_id":"11111111-1111-4111-8111-111111111111","primary":"node-a","controller_node":"node-a","state_dir":"/var/lib/hat/state","replica_reads":false,"required_databases":["main","session","aux"],"nodes":[{"id":"node-a","endpoint":"http://127.0.0.1:18080","data_dir":"/var/lib/hat/node-a"},{"id":"node-b","endpoint":"http://127.0.0.1:18081","data_dir":"/var/lib/hat/node-b"}]}"#,
    )
    .unwrap()
}

fn temp_root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("hat-task7-{label}-{suffix}"));
    fs::create_dir(&path).unwrap();
    path
}

fn restore_request() -> RestoreRequest {
    RestoreRequest {
        cluster_id: CLUSTER.into(),
        database: "main".into(),
        history_id: "history-a".into(),
        position: 7,
        schema_digest: "schema-a".into(),
        config_digest: "config-a".into(),
        key_version: "key-a".into(),
        application_marker: "app-ok".into(),
        auth_marker: "auth-ok".into(),
    }
}

fn restore_fixture(root: &Path) -> (RestoreRequest, PathBuf, PathBuf) {
    let source = root.join("source");
    let destination = root.join("candidate");
    fs::create_dir(&source).unwrap();
    let payload = br#"{"schema_version":1,"application_ok":true,"auth_ok":true,"application_schema_digest":"schema-a","application_config_digest":"config-a","auth_key_version":"key-a","application_marker":"app-ok","auth_marker":"auth-ok"}"#;
    fs::write(source.join("payload.bin"), payload).unwrap();
    let hash: String = Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    fs::write(source.join("manifest.json"), format!(
        r#"{{"schema_version":1,"cluster_id":"{CLUSTER}","database":"main","history_id":"history-a","position":7,"schema_digest":"schema-a","config_digest":"config-a","key_version":"key-a","payload_bytes":{},"payload_sha256":"{}"}}"#,
        payload.len(), hash
    )).unwrap();
    let request = restore_request();
    (request, source, destination)
}

fn spec(root: &Path, restore: RestoreRequest) -> SwitchoverSpec {
    SwitchoverSpec {
        request_id: "request-switchover".into(),
        operation_id: "operation-switchover".into(),
        digest: "switchover-digest".into(),
        old_node_id: "node-a".into(),
        candidate_node_id: "node-b".into(),
        old_incarnation: OLD_INCARNATION.into(),
        candidate_incarnation: NEW_INCARNATION.into(),
        old_writer_epoch: 1,
        new_writer_epoch: 2,
        fence_action_id: ACTION.into(),
        evidence_nonce: EVIDENCE.into(),
        expected_generation: 1,
        new_generation: 2,
        release_digest: RELEASE.into(),
        config_digest: CONFIG_DIGEST.into(),
        restore,
        restore_source: root.join("source"),
        destination: root.join("candidate"),
    }
}

fn evidence() -> FenceEvidence {
    FenceEvidence {
        operation_id: "operation-switchover".into(),
        action_id: ACTION.into(),
        target: "node-a".into(),
        incarnation: OLD_INCARNATION.into(),
        evidence_nonce: EVIDENCE.into(),
        settled: true,
    }
}

fn harness(root: &Path) -> (PlannedSwitchover, Journal) {
    let config = config();
    let old_node = NodeState::new(CLUSTER, "node-a", OLD_INCARNATION, NodeRole::Primary).unwrap();
    let mut old = NodeRuntime::new(old_node);
    old.children
        .spawn("trailbase", Command::new("sh").arg("-c").arg("sleep 10"))
        .unwrap();
    old.children
        .spawn("uploader", Command::new("sh").arg("-c").arg("sleep 10"))
        .unwrap();
    let candidate_node =
        NodeState::new(CLUSTER, "node-b", NEW_INCARNATION, NodeRole::Standby).unwrap();
    let mut candidate = NodeRuntime::new(candidate_node);
    candidate
        .children
        .spawn("follower", Command::new("sh").arg("-c").arg("sleep 10"))
        .unwrap();
    let old_route = Route::for_node(
        &config,
        "node-a",
        1,
        1,
        OLD_INCARNATION,
        RELEASE,
        CONFIG_DIGEST,
    )
    .unwrap();
    let mut routes = RouteTable::new(&config);
    routes.install(old_route).unwrap();
    let (restore, _source, _destination) = restore_fixture(root);
    let operation = PlannedSwitchover::new(config, routes, old, candidate, spec(root, restore));
    let journal = Journal::open(root.join("journal.db"), "task7-test").unwrap();
    (operation, journal)
}

#[test]
fn planned_switchover_quiesces_old_writer_before_candidate_admission_and_replaces_route_once() {
    let root = temp_root("success");
    let (mut operation, mut journal) = harness(&root);
    let receipt = operation
        .execute(&mut journal, &evidence(), FaultPoint::None)
        .unwrap();
    let old_revision = operation.old().node.revision();
    assert_eq!(receipt.operation_id, "operation-switchover");
    assert_eq!(operation.old().node.admission(), Admission::Closed);
    assert_eq!(
        operation.old_mut().children.state("trailbase").unwrap(),
        ChildState::Missing
    );
    assert_eq!(
        operation.old_mut().children.state("uploader").unwrap(),
        ChildState::Missing
    );
    assert_eq!(
        operation
            .candidate_mut()
            .children
            .state("follower")
            .unwrap(),
        ChildState::Missing
    );
    assert_eq!(operation.candidate().node.admission(), Admission::Open);
    assert!(operation.old().node.quarantined());
    assert_eq!(
        operation
            .old_mut()
            .node
            .activate(&hat::node::ActivationGrant {
                cluster_id: CLUSTER.into(),
                node_id: "node-a".into(),
                incarnation: OLD_INCARNATION.into(),
                writer_epoch: 99
            }),
        Err(hat::node::NodeError::Quarantined)
    );
    assert_eq!(
        operation.routes().active().unwrap().primary_node_id(),
        "node-b"
    );
    assert!(operation.destination().join("payload.bin").is_file());
    assert_eq!(
        operation.execute(&mut journal, &evidence(), FaultPoint::None),
        Ok(hat::operations::SwitchoverReceipt {
            request_id: "request-switchover".into(),
            operation_id: "operation-switchover".into(),
            state: "succeeded".into()
        })
    );
    assert_eq!(operation.old().node.revision(), old_revision);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn lost_or_failed_boundaries_block_conflicting_work_without_reviving_old_writer() {
    for fault in [
        FaultPoint::AfterAdmissionClosed,
        FaultPoint::AfterFence,
        FaultPoint::AfterRestore,
        FaultPoint::AfterRoutePublication,
        FaultPoint::LostFenceResponse,
        FaultPoint::LostRestoreResponse,
        FaultPoint::LostRouteResponse,
    ] {
        let root = temp_root("fault");
        let (mut operation, mut journal) = harness(&root);
        let result = operation.execute(&mut journal, &evidence(), fault);
        assert_eq!(result, Err(SwitchoverError::BlockedUncertain));
        let old_revision = operation.old().node.revision();
        assert_eq!(operation.old().node.admission(), Admission::Closed);
        assert!(operation.old().node.quarantined());
        assert_eq!(
            operation
                .old_mut()
                .node
                .activate(&hat::node::ActivationGrant {
                    cluster_id: CLUSTER.into(),
                    node_id: "node-a".into(),
                    incarnation: OLD_INCARNATION.into(),
                    writer_epoch: 99
                }),
            Err(hat::node::NodeError::Quarantined)
        );
        assert_eq!(
            journal.submit("other-request", "other-operation", "other-digest"),
            Err(hat::journal::JournalError::Uncertain)
        );
        assert_eq!(
            journal
                .receipt("request-switchover")
                .unwrap()
                .unwrap()
                .state,
            "blocked_uncertain"
        );
        assert!(matches!(
            operation.execute(&mut journal, &evidence(), fault),
            Err(SwitchoverError::ExistingBlocked(receipt)) if receipt.state == "blocked_uncertain"
        ));
        assert_eq!(operation.old().node.revision(), old_revision);
        if matches!(
            fault,
            FaultPoint::AfterRoutePublication | FaultPoint::LostRouteResponse
        ) {
            assert_eq!(operation.candidate().node.admission(), Admission::Open);
        } else {
            assert_eq!(operation.candidate().node.admission(), Admission::Closed);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn reconciliation_reconstructs_node_state_after_controller_and_node_restart() {
    let root = temp_root("reconcile-restart");
    let (planned, mut journal) = harness(&root);
    let mut failover = ManualFailover::new(planned, true, loss_report());
    assert_eq!(
        failover.execute(
            &mut journal,
            &evidence(),
            FaultPoint::AfterCandidateActivation
        ),
        Err(FailoverError::Switchover(SwitchoverError::BlockedUncertain))
    );
    drop(journal);
    drop(failover);

    let config = config();
    let old = NodeRuntime::new(
        NodeState::new(CLUSTER, "node-a", OLD_INCARNATION, NodeRole::Primary).unwrap(),
    );
    let candidate = NodeRuntime::new(
        NodeState::new(CLUSTER, "node-b", NEW_INCARNATION, NodeRole::Standby).unwrap(),
    );
    let old_route = Route::for_node(
        &config,
        "node-a",
        1,
        1,
        OLD_INCARNATION,
        RELEASE,
        CONFIG_DIGEST,
    )
    .unwrap();
    let mut routes = RouteTable::new(&config);
    routes.install(old_route).unwrap();
    let planned = PlannedSwitchover::new(
        config,
        routes,
        old,
        candidate,
        spec(&root, restore_request()),
    );
    let mut recovered = ManualFailover::new(planned, true, loss_report());
    let mut journal = Journal::open(root.join("journal.db"), "task8-node-restart").unwrap();
    let receipt = recovered
        .reconcile(
            &mut journal,
            &ReconcileEvidence {
                operation_id: "operation-switchover".into(),
                candidate_node_id: "node-b".into(),
                candidate_incarnation: NEW_INCARNATION.into(),
                candidate_active: true,
                candidate_follower_stopped: true,
                candidate_writer_epoch: 2,
                old_quarantined: true,
                old_children_stopped: true,
                fence_settled: true,
                fence_action_id: ACTION.into(),
                fence_target: "node-a".into(),
                fence_incarnation: OLD_INCARNATION.into(),
                fence_evidence_nonce: EVIDENCE.into(),
                route_published: false,
                route_generation: 2,
                route_node_id: "node-b".into(),
                route_incarnation: NEW_INCARNATION.into(),
                route_writer_epoch: 2,
            },
        )
        .unwrap();
    assert_eq!(receipt.switchover.state, "succeeded");
    assert!(recovered.old().node.quarantined());
    assert_eq!(recovered.candidate().node.admission(), Admission::Open);
    assert_eq!(
        recovered.routes().active().unwrap().primary_node_id(),
        "node-b"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsettled_or_wrong_fence_evidence_refuses_before_candidate_activation() {
    let root = temp_root("fence-refuse");
    let (mut operation, mut journal) = harness(&root);
    let mut evidence = evidence();
    evidence.settled = false;
    assert_eq!(
        operation.execute(&mut journal, &evidence, FaultPoint::None),
        Err(SwitchoverError::BlockedUncertain)
    );
    assert_eq!(operation.candidate().node.admission(), Admission::Closed);
    assert_eq!(
        journal
            .receipt("request-switchover")
            .unwrap()
            .unwrap()
            .state,
        "blocked_uncertain"
    );
    assert_eq!(
        journal.submit("other-request", "other-operation", "other-digest"),
        Err(hat::journal::JournalError::Uncertain)
    );
    assert!(matches!(
        operation.execute(&mut journal, &evidence, FaultPoint::None),
        Err(SwitchoverError::ExistingBlocked(receipt)) if receipt.state == "blocked_uncertain"
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restore_failure_blocks_the_operation_before_candidate_activation() {
    let root = temp_root("restore-failure");
    let (mut operation, mut journal) = harness(&root);
    fs::remove_dir_all(root.join("source")).unwrap();
    assert!(matches!(
        operation.execute(&mut journal, &evidence(), FaultPoint::None),
        Err(SwitchoverError::Restore(
            hat::restore::RestoreError::MissingSource
        ))
    ));
    assert_eq!(operation.candidate().node.admission(), Admission::Closed);
    assert_eq!(
        journal.submit("other-request", "other-operation", "other-digest"),
        Err(hat::journal::JournalError::Uncertain)
    );
    fs::remove_dir_all(root).unwrap();
}

fn loss_report() -> LossReport {
    LossReport {
        possible_loss: LossBound::Unknown,
    }
}

#[test]
fn manual_failover_requires_loss_acceptance_and_settled_fence_without_inventing_loss() {
    let root = temp_root("failover-refuse");
    let (planned, mut journal) = harness(&root);
    let mut failover = ManualFailover::new(planned, false, loss_report());
    assert_eq!(
        failover.execute(&mut journal, &evidence(), FaultPoint::None),
        Err(FailoverError::PossibleLossNotAccepted)
    );
    assert!(journal.receipt("request-switchover").unwrap().is_none());
    fs::remove_dir_all(root).unwrap();

    let root = temp_root("failover-unknown");
    let (planned, mut journal) = harness(&root);
    let mut failover = ManualFailover::new(planned, true, loss_report());
    let mut unsettled = evidence();
    unsettled.settled = false;
    assert_eq!(
        failover.execute(&mut journal, &unsettled, FaultPoint::None),
        Err(FailoverError::Switchover(SwitchoverError::BlockedUncertain))
    );
    assert_eq!(
        journal.submit("other-request", "other-operation", "other-digest"),
        Err(hat::journal::JournalError::Uncertain)
    );
    fs::remove_dir_all(root).unwrap();

    let root = temp_root("failover-success");
    let (planned, mut journal) = harness(&root);
    let mut failover = ManualFailover::new(planned, true, loss_report());
    let receipt = failover
        .execute(&mut journal, &evidence(), FaultPoint::None)
        .unwrap();
    assert_eq!(receipt.loss, loss_report());
    assert_eq!(
        failover.routes().active().unwrap().primary_node_id(),
        "node-b"
    );
    let replay = failover
        .execute(&mut journal, &evidence(), FaultPoint::None)
        .unwrap();
    assert_eq!(replay.switchover.state, "succeeded");
    assert_eq!(replay.loss, loss_report());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reconciliation_reopens_the_same_operation_but_unresolved_activation_stays_blocked() {
    let root = temp_root("reconcile");
    let (planned, journal) = harness(&root);
    let journal_path = root.join("journal.db");
    let mut failover = ManualFailover::new(planned, true, loss_report());
    let mut journal = journal;
    assert_eq!(
        failover.execute(
            &mut journal,
            &evidence(),
            FaultPoint::AfterCandidateActivation
        ),
        Err(FailoverError::Switchover(SwitchoverError::BlockedUncertain))
    );
    assert_eq!(failover.candidate().node.admission(), Admission::Open);
    assert_eq!(
        failover.routes().active().unwrap().primary_node_id(),
        "node-a"
    );
    drop(journal);
    let mut journal = Journal::open(&journal_path, "task8-reopen").unwrap();
    let inspection = failover.inspect(&journal).unwrap();
    assert_eq!(inspection.state.as_deref(), Some("blocked_uncertain"));
    let receipt = failover
        .reconcile(
            &mut journal,
            &ReconcileEvidence {
                operation_id: "operation-switchover".into(),
                candidate_node_id: "node-b".into(),
                candidate_incarnation: NEW_INCARNATION.into(),
                candidate_active: true,
                candidate_follower_stopped: true,
                candidate_writer_epoch: 2,
                old_quarantined: true,
                old_children_stopped: true,
                fence_settled: true,
                fence_action_id: ACTION.into(),
                fence_target: "node-a".into(),
                fence_incarnation: OLD_INCARNATION.into(),
                fence_evidence_nonce: EVIDENCE.into(),
                route_published: false,
                route_generation: 2,
                route_node_id: "node-b".into(),
                route_incarnation: NEW_INCARNATION.into(),
                route_writer_epoch: 2,
            },
        )
        .unwrap();
    assert_eq!(receipt.switchover.state, "succeeded");
    assert_eq!(
        failover.routes().active().unwrap().primary_node_id(),
        "node-b"
    );
    assert_eq!(
        journal
            .receipt("request-switchover")
            .unwrap()
            .unwrap()
            .state,
        "succeeded"
    );
    let replay = failover
        .reconcile(
            &mut journal,
            &ReconcileEvidence {
                operation_id: "operation-switchover".into(),
                candidate_node_id: "node-b".into(),
                candidate_incarnation: NEW_INCARNATION.into(),
                candidate_active: true,
                candidate_follower_stopped: true,
                candidate_writer_epoch: 2,
                old_quarantined: true,
                old_children_stopped: true,
                fence_settled: true,
                fence_action_id: ACTION.into(),
                fence_target: "node-a".into(),
                fence_incarnation: OLD_INCARNATION.into(),
                fence_evidence_nonce: EVIDENCE.into(),
                route_published: true,
                route_generation: 2,
                route_node_id: "node-b".into(),
                route_incarnation: NEW_INCARNATION.into(),
                route_writer_epoch: 2,
            },
        )
        .unwrap();
    assert_eq!(replay.switchover.state, "succeeded");
    fs::remove_dir_all(root).unwrap();

    let root = temp_root("reconcile-unresolved");
    let (planned, mut journal) = harness(&root);
    let mut failover = ManualFailover::new(planned, true, loss_report());
    assert_eq!(
        failover.execute(&mut journal, &evidence(), FaultPoint::AfterRestore),
        Err(FailoverError::Switchover(SwitchoverError::BlockedUncertain))
    );
    assert_eq!(
        failover.reconcile(
            &mut journal,
            &ReconcileEvidence {
                operation_id: "operation-switchover".into(),
                candidate_node_id: "node-b".into(),
                candidate_incarnation: NEW_INCARNATION.into(),
                candidate_active: false,
                candidate_follower_stopped: true,
                candidate_writer_epoch: 2,
                old_quarantined: true,
                old_children_stopped: true,
                fence_settled: true,
                fence_action_id: ACTION.into(),
                fence_target: "node-a".into(),
                fence_incarnation: OLD_INCARNATION.into(),
                fence_evidence_nonce: EVIDENCE.into(),
                route_published: false,
                route_generation: 2,
                route_node_id: "node-b".into(),
                route_incarnation: NEW_INCARNATION.into(),
                route_writer_epoch: 2,
            },
        ),
        Err(FailoverError::Unresolved)
    );
    assert_eq!(
        journal.submit("other-request", "other-operation", "other-digest"),
        Err(hat::journal::JournalError::Uncertain)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quarantined_former_primary_reseeds_to_a_fresh_closed_standby_without_mutating_source() {
    let root = temp_root("rejoin");
    let (mut operation, mut journal) = harness(&root);
    assert_eq!(
        operation.execute(&mut journal, &evidence(), FaultPoint::AfterFence),
        Err(SwitchoverError::BlockedUncertain)
    );
    let source_manifest = fs::read(root.join("source/manifest.json")).unwrap();
    let source_payload = fs::read(root.join("source/payload.bin")).unwrap();
    let destination = root.join("rejoined");
    let (mut rejoined, receipt) = hat::operations::reseed_rejoin(
        operation.old_mut(),
        &RejoinSpec {
            cluster_id: CLUSTER.into(),
            node_id: "node-a".into(),
            incarnation: "66666666-6666-4666-8666-666666666666".into(),
            restore: restore_request(),
            restore_source: root.join("source"),
            destination: destination.clone(),
        },
    )
    .unwrap();
    assert_eq!(receipt.destination, destination);
    assert_eq!(rejoined.node.role(), NodeRole::Standby);
    assert_eq!(rejoined.node.admission(), Admission::Closed);
    assert_eq!(
        rejoined.node.activate(&hat::node::ActivationGrant {
            cluster_id: CLUSTER.into(),
            node_id: "node-a".into(),
            incarnation: "66666666-6666-4666-8666-666666666666".into(),
            writer_epoch: 9,
        }),
        Err(hat::node::NodeError::StandbyActivation)
    );
    assert_eq!(
        operation
            .old_mut()
            .node
            .activate(&hat::node::ActivationGrant {
                cluster_id: CLUSTER.into(),
                node_id: "node-a".into(),
                incarnation: OLD_INCARNATION.into(),
                writer_epoch: 9,
            }),
        Err(hat::node::NodeError::Quarantined)
    );
    assert_eq!(
        source_manifest,
        fs::read(root.join("source/manifest.json")).unwrap()
    );
    assert_eq!(
        source_payload,
        fs::read(root.join("source/payload.bin")).unwrap()
    );
    assert!(destination.join("payload.bin").is_file());
    fs::remove_dir_all(root).unwrap();
}
