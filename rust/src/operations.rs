use crate::{
    config::{is_uuid, Config},
    journal::{Journal, JournalError},
    node::{ActivationGrant, Admission, NodeError, NodeRole, NodeRuntime, NodeState},
    restore::{validate_and_restore, RestoreError, RestoreRequest},
    routing::{Route, RouteError, RouteTable},
};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceEvidence {
    pub operation_id: String,
    pub action_id: String,
    pub target: String,
    pub incarnation: String,
    pub evidence_nonce: String,
    pub settled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    None,
    AfterAdmissionClosed,
    AfterFence,
    AfterRestore,
    AfterRoutePublication,
    AfterCandidateActivation,
    LostFenceResponse,
    LostRestoreResponse,
    LostRouteResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchoverSpec {
    pub request_id: String,
    pub operation_id: String,
    pub digest: String,
    pub old_node_id: String,
    pub candidate_node_id: String,
    pub old_incarnation: String,
    pub candidate_incarnation: String,
    pub old_writer_epoch: u64,
    pub new_writer_epoch: u64,
    pub fence_action_id: String,
    pub evidence_nonce: String,
    pub expected_generation: u64,
    pub new_generation: u64,
    pub release_digest: String,
    pub config_digest: String,
    pub restore: RestoreRequest,
    pub restore_source: PathBuf,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossBound {
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossReport {
    pub possible_loss: LossBound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileEvidence {
    pub operation_id: String,
    pub candidate_node_id: String,
    pub candidate_incarnation: String,
    pub candidate_active: bool,
    pub candidate_follower_stopped: bool,
    pub candidate_writer_epoch: u64,
    pub old_quarantined: bool,
    pub old_children_stopped: bool,
    pub fence_settled: bool,
    pub fence_action_id: String,
    pub fence_target: String,
    pub fence_incarnation: String,
    pub fence_evidence_nonce: String,
    pub route_published: bool,
    pub route_generation: u64,
    pub route_node_id: String,
    pub route_incarnation: String,
    pub route_writer_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejoinSpec {
    pub cluster_id: String,
    pub node_id: String,
    pub incarnation: String,
    pub restore: RestoreRequest,
    pub restore_source: PathBuf,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejoinReceipt {
    pub node_id: String,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationInspection {
    pub request_id: String,
    pub operation_id: String,
    pub state: Option<String>,
    pub candidate_active: Admission,
    pub old_quarantined: bool,
    pub route_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualFailoverReceipt {
    pub switchover: SwitchoverReceipt,
    pub loss: LossReport,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FailoverError {
    PossibleLossNotAccepted,
    Unresolved,
    Switchover(SwitchoverError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RejoinError {
    InvalidInput,
    NotQuarantined,
    AdmissionOpen,
    ChildrenRunning,
    Restore(RestoreError),
    Node,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchoverReceipt {
    pub request_id: String,
    pub operation_id: String,
    pub state: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwitchoverError {
    InvalidInput,
    Conflict,
    BlockedUncertain,
    ExistingActive(crate::journal::OperationReceipt),
    ExistingBlocked(crate::journal::OperationReceipt),
    Journal,
    FenceEvidence,
    Restore(RestoreError),
    Node,
    Child,
    Route,
}

pub struct PlannedSwitchover {
    config: Config,
    routes: RouteTable,
    old: NodeRuntime,
    candidate: NodeRuntime,
    spec: SwitchoverSpec,
    failover_policy: bool,
}

pub struct ManualFailover {
    inner: PlannedSwitchover,
    possible_loss_accepted: bool,
    loss: LossReport,
}

impl PlannedSwitchover {
    pub fn new(
        config: Config,
        routes: RouteTable,
        old: NodeRuntime,
        candidate: NodeRuntime,
        spec: SwitchoverSpec,
    ) -> Self {
        Self {
            config,
            routes,
            old,
            candidate,
            spec,
            failover_policy: false,
        }
    }

    pub fn execute(
        &mut self,
        journal: &mut Journal,
        evidence: &FenceEvidence,
        fault: FaultPoint,
    ) -> Result<SwitchoverReceipt, SwitchoverError> {
        if journal
            .receipt(&self.spec.request_id)
            .map_err(|_| SwitchoverError::Journal)?
            .is_some()
        {
            return match journal.submit_with_policy(
                &self.spec.request_id,
                &self.spec.operation_id,
                &self.spec.digest,
                self.failover_policy,
            ) {
                Ok(receipt) if receipt.state == "succeeded" => Ok(SwitchoverReceipt {
                    request_id: receipt.request_id,
                    operation_id: receipt.operation_id,
                    state: receipt.state,
                }),
                Ok(receipt) if receipt.state == "blocked_uncertain" => {
                    Err(SwitchoverError::ExistingBlocked(receipt))
                }
                Ok(receipt) => Err(SwitchoverError::ExistingActive(receipt)),
                Err(JournalError::Conflict | JournalError::PolicyConflict) => {
                    Err(SwitchoverError::Conflict)
                }
                Err(_) => Err(SwitchoverError::Journal),
            };
        }
        self.validate_spec()?;
        if let Err(error) = journal.submit_with_policy(
            &self.spec.request_id,
            &self.spec.operation_id,
            &self.spec.digest,
            self.failover_policy,
        ) {
            if matches!(error, JournalError::Uncertain) {
                self.old.node.quarantine();
            }
            return Err(match error {
                JournalError::Conflict | JournalError::PolicyConflict => SwitchoverError::Conflict,
                JournalError::Uncertain => SwitchoverError::BlockedUncertain,
                _ => SwitchoverError::Journal,
            });
        }

        self.old.node.close_admission();
        if Self::stop_child(&mut self.old, "trailbase").is_err()
            || Self::stop_child(&mut self.old, "uploader").is_err()
            || Self::stop_child(&mut self.candidate, "follower").is_err()
        {
            return Err(self.block(journal));
        }
        if fault == FaultPoint::AfterAdmissionClosed {
            return Err(self.block(journal));
        }
        if !self.valid_evidence(evidence) {
            return Err(self.block(journal));
        }
        self.old.node.quarantine();
        if matches!(
            fault,
            FaultPoint::AfterFence | FaultPoint::LostFenceResponse
        ) {
            return Err(self.block(journal));
        }

        if let Err(error) = validate_and_restore(
            &self.spec.restore_source,
            &self.spec.destination,
            &self.spec.restore,
        ) {
            if journal.block_uncertain(&self.spec.operation_id).is_err() {
                return Err(SwitchoverError::Journal);
            }
            return Err(SwitchoverError::Restore(error));
        }
        if matches!(
            fault,
            FaultPoint::AfterRestore | FaultPoint::LostRestoreResponse
        ) {
            return Err(self.block(journal));
        }
        if self.old.children.state("trailbase").ok() != Some(crate::node::ChildState::Missing)
            || self.old.children.state("uploader").ok() != Some(crate::node::ChildState::Missing)
            || self.candidate.children.state("follower").ok()
                != Some(crate::node::ChildState::Missing)
            || self.candidate.node.admission() != Admission::Closed
        {
            return Err(self.block(journal));
        }
        self.candidate
            .node
            .promote_to_primary()
            .map_err(|_| self.block(journal))?;
        let grant = ActivationGrant {
            cluster_id: self.config.cluster_id().to_owned(),
            node_id: self.spec.candidate_node_id.clone(),
            incarnation: self.spec.candidate_incarnation.clone(),
            writer_epoch: self.spec.new_writer_epoch,
        };
        self.candidate
            .node
            .activate(&grant)
            .map_err(|_| self.block(journal))?;
        if fault == FaultPoint::AfterCandidateActivation {
            return Err(self.block(journal));
        }

        let route = Route::for_node(
            &self.config,
            &self.spec.candidate_node_id,
            self.spec.new_generation,
            self.spec.new_writer_epoch,
            &self.spec.candidate_incarnation,
            &self.spec.release_digest,
            &self.spec.config_digest,
        )
        .map_err(|_| self.block(journal))?;
        self.routes
            .install(route)
            .map_err(|_| self.block(journal))?;
        if matches!(
            fault,
            FaultPoint::AfterRoutePublication | FaultPoint::LostRouteResponse
        ) {
            return Err(self.block(journal));
        }
        journal
            .finish(&self.spec.operation_id, "succeeded")
            .map_err(|_| SwitchoverError::Journal)?;
        Ok(SwitchoverReceipt {
            request_id: self.spec.request_id.clone(),
            operation_id: self.spec.operation_id.clone(),
            state: "succeeded".into(),
        })
    }

    pub fn old(&self) -> &NodeRuntime {
        &self.old
    }

    pub fn old_mut(&mut self) -> &mut NodeRuntime {
        &mut self.old
    }

    pub fn candidate(&self) -> &NodeRuntime {
        &self.candidate
    }

    pub fn candidate_mut(&mut self) -> &mut NodeRuntime {
        &mut self.candidate
    }

    pub fn routes(&self) -> &RouteTable {
        &self.routes
    }

    pub fn destination(&self) -> &PathBuf {
        &self.spec.destination
    }

    fn stop_child(runtime: &mut NodeRuntime, name: &str) -> Result<(), ()> {
        runtime.stop_child(name).map(|_| ()).map_err(|_| ())
    }

    fn valid_evidence(&self, evidence: &FenceEvidence) -> bool {
        evidence.operation_id == self.spec.operation_id
            && evidence.action_id == self.spec.fence_action_id
            && evidence.target == self.spec.old_node_id
            && evidence.incarnation == self.spec.old_incarnation
            && evidence.evidence_nonce == self.spec.evidence_nonce
            && is_uuid(&evidence.action_id)
            && is_uuid(&evidence.evidence_nonce)
            && evidence.settled
    }

    fn validate_spec(&self) -> Result<(), SwitchoverError> {
        if self.spec.old_node_id == self.spec.candidate_node_id
            || !is_uuid(&self.spec.old_incarnation)
            || !is_uuid(&self.spec.candidate_incarnation)
            || self.spec.old_writer_epoch == 0
            || self.spec.new_writer_epoch <= self.spec.old_writer_epoch
            || !is_uuid(&self.spec.fence_action_id)
            || !is_uuid(&self.spec.evidence_nonce)
            || self.spec.new_generation <= self.spec.expected_generation
            || self.spec.restore.cluster_id != self.config.cluster_id()
            || self.spec.restore.database.is_empty()
        {
            return Err(SwitchoverError::InvalidInput);
        }
        let Some(route) = self.routes.active() else {
            return Err(SwitchoverError::InvalidInput);
        };
        if route.primary_node_id() != self.spec.old_node_id
            || route.writer_epoch() != self.spec.old_writer_epoch
            || route.primary_incarnation() != self.spec.old_incarnation
            || route.generation() != self.spec.expected_generation
        {
            return Err(SwitchoverError::InvalidInput);
        }
        Ok(())
    }

    fn block(&mut self, journal: &mut Journal) -> SwitchoverError {
        self.old.node.quarantine();
        if journal.block_uncertain(&self.spec.operation_id).is_ok() {
            SwitchoverError::BlockedUncertain
        } else {
            SwitchoverError::Journal
        }
    }
}

impl ManualFailover {
    pub fn new(
        mut inner: PlannedSwitchover,
        possible_loss_accepted: bool,
        loss: LossReport,
    ) -> Self {
        inner.failover_policy = true;
        Self {
            inner,
            possible_loss_accepted,
            loss,
        }
    }

    pub fn execute(
        &mut self,
        journal: &mut Journal,
        evidence: &FenceEvidence,
        fault: FaultPoint,
    ) -> Result<ManualFailoverReceipt, FailoverError> {
        if !self.possible_loss_accepted {
            return Err(FailoverError::PossibleLossNotAccepted);
        }
        let switchover = self
            .inner
            .execute(journal, evidence, fault)
            .map_err(FailoverError::Switchover)?;
        Ok(ManualFailoverReceipt {
            switchover,
            loss: self.loss.clone(),
        })
    }

    pub fn inspect(&self, journal: &Journal) -> Result<OperationInspection, FailoverError> {
        let receipt = journal
            .receipt(&self.inner.spec.request_id)
            .map_err(|_| FailoverError::Switchover(SwitchoverError::Journal))?;
        Ok(OperationInspection {
            request_id: self.inner.spec.request_id.clone(),
            operation_id: self.inner.spec.operation_id.clone(),
            state: receipt.map(|value| value.state),
            candidate_active: self.inner.candidate.node.admission(),
            old_quarantined: self.inner.old.node.quarantined(),
            route_generation: self.inner.routes.active().map(Route::generation),
        })
    }

    pub fn reconcile(
        &mut self,
        journal: &mut Journal,
        evidence: &ReconcileEvidence,
    ) -> Result<ManualFailoverReceipt, FailoverError> {
        if !self.possible_loss_accepted {
            return Err(FailoverError::PossibleLossNotAccepted);
        }
        let Some(receipt) = journal
            .retained(
                &self.inner.spec.request_id,
                &self.inner.spec.operation_id,
                &self.inner.spec.digest,
                true,
            )
            .map_err(|error| match error {
                JournalError::PolicyConflict | JournalError::Conflict => FailoverError::Unresolved,
                _ => FailoverError::Switchover(SwitchoverError::Journal),
            })?
        else {
            return Err(FailoverError::Unresolved);
        };
        if receipt.state == "succeeded" {
            return Ok(ManualFailoverReceipt {
                switchover: SwitchoverReceipt {
                    request_id: receipt.request_id,
                    operation_id: receipt.operation_id,
                    state: receipt.state,
                },
                loss: self.loss.clone(),
            });
        }
        if receipt.operation_id != self.inner.spec.operation_id
            || receipt.state != "blocked_uncertain"
            || evidence.operation_id != self.inner.spec.operation_id
            || evidence.candidate_node_id != self.inner.spec.candidate_node_id
            || evidence.candidate_incarnation != self.inner.spec.candidate_incarnation
            || evidence.candidate_writer_epoch != self.inner.spec.new_writer_epoch
            || !evidence.fence_settled
            || evidence.fence_action_id != self.inner.spec.fence_action_id
            || evidence.fence_target != self.inner.spec.old_node_id
            || evidence.fence_incarnation != self.inner.spec.old_incarnation
            || evidence.fence_evidence_nonce != self.inner.spec.evidence_nonce
            || !is_uuid(&evidence.fence_action_id)
            || !is_uuid(&evidence.fence_evidence_nonce)
            || !evidence.candidate_active
            || !evidence.candidate_follower_stopped
            || !evidence.old_quarantined
            || !evidence.old_children_stopped
            || evidence.route_generation != self.inner.spec.new_generation
            || evidence.route_node_id != self.inner.spec.candidate_node_id
            || evidence.route_incarnation != self.inner.spec.candidate_incarnation
            || evidence.route_writer_epoch != self.inner.spec.new_writer_epoch
        {
            return Err(FailoverError::Unresolved);
        }
        if !self.inner.old.node.quarantined() {
            self.inner.old.node.quarantine();
        }
        if self.inner.candidate.node.admission() != Admission::Open {
            self.inner
                .candidate
                .node
                .adopt_observed_primary(&ActivationGrant {
                    cluster_id: self.inner.config.cluster_id().to_owned(),
                    node_id: self.inner.spec.candidate_node_id.clone(),
                    incarnation: self.inner.spec.candidate_incarnation.clone(),
                    writer_epoch: self.inner.spec.new_writer_epoch,
                })
                .map_err(|_| FailoverError::Unresolved)?;
        } else if self.inner.candidate.node.role() != NodeRole::Primary
            || self.inner.candidate.node.writer_epoch() != Some(self.inner.spec.new_writer_epoch)
            || self.inner.candidate.node.cluster_id() != self.inner.config.cluster_id()
            || self.inner.candidate.node.node_id() != self.inner.spec.candidate_node_id
            || self.inner.candidate.node.incarnation() != self.inner.spec.candidate_incarnation
        {
            return Err(FailoverError::Unresolved);
        }
        let route_matches = self.inner.routes.active().is_some_and(|route| {
            route.primary_node_id() == self.inner.spec.candidate_node_id
                && route.primary_incarnation() == self.inner.spec.candidate_incarnation
                && route.writer_epoch() == self.inner.spec.new_writer_epoch
                && route.generation() == self.inner.spec.new_generation
        });
        if evidence.route_published && !route_matches {
            return Err(FailoverError::Unresolved);
        }
        if !route_matches {
            let route = Route::for_node(
                &self.inner.config,
                &self.inner.spec.candidate_node_id,
                self.inner.spec.new_generation,
                self.inner.spec.new_writer_epoch,
                &self.inner.spec.candidate_incarnation,
                &self.inner.spec.release_digest,
                &self.inner.spec.config_digest,
            )
            .map_err(|_| FailoverError::Unresolved)?;
            self.inner
                .routes
                .install(route)
                .map_err(|_| FailoverError::Unresolved)?;
        }
        journal
            .reconcile(&self.inner.spec.operation_id)
            .map_err(|_| FailoverError::Switchover(SwitchoverError::Journal))?;
        Ok(ManualFailoverReceipt {
            switchover: SwitchoverReceipt {
                request_id: self.inner.spec.request_id.clone(),
                operation_id: self.inner.spec.operation_id.clone(),
                state: "succeeded".into(),
            },
            loss: self.loss.clone(),
        })
    }

    pub fn old(&self) -> &NodeRuntime {
        &self.inner.old
    }

    pub fn candidate(&self) -> &NodeRuntime {
        &self.inner.candidate
    }

    pub fn routes(&self) -> &RouteTable {
        &self.inner.routes
    }
}

pub fn reseed_rejoin(
    old: &mut NodeRuntime,
    spec: &RejoinSpec,
) -> Result<(NodeRuntime, RejoinReceipt), RejoinError> {
    if !is_uuid(&spec.cluster_id)
        || !is_uuid(&spec.incarnation)
        || spec.node_id.is_empty()
        || old.node.cluster_id() != spec.cluster_id
        || old.node.node_id() != spec.node_id
        || spec.restore.cluster_id != spec.cluster_id
    {
        return Err(RejoinError::InvalidInput);
    }
    if !old.node.quarantined() {
        return Err(RejoinError::NotQuarantined);
    }
    if old.node.admission() != Admission::Closed {
        return Err(RejoinError::AdmissionOpen);
    }
    if !old.children.is_empty() {
        return Err(RejoinError::ChildrenRunning);
    }
    validate_and_restore(&spec.restore_source, &spec.destination, &spec.restore)
        .map_err(RejoinError::Restore)?;
    let node = NodeState::new(
        &spec.cluster_id,
        &spec.node_id,
        &spec.incarnation,
        NodeRole::Standby,
    )
    .map_err(|_| RejoinError::Node)?;
    Ok((
        NodeRuntime::new(node),
        RejoinReceipt {
            node_id: spec.node_id.clone(),
            destination: spec.destination.clone(),
        },
    ))
}

impl From<JournalError> for SwitchoverError {
    fn from(_: JournalError) -> Self {
        Self::Journal
    }
}

impl From<NodeError> for SwitchoverError {
    fn from(_: NodeError) -> Self {
        Self::Node
    }
}

impl From<RouteError> for SwitchoverError {
    fn from(_: RouteError) -> Self {
        Self::Route
    }
}
