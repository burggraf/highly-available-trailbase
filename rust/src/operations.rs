use crate::{
    config::{is_uuid, Config},
    journal::{Journal, JournalError},
    node::{ActivationGrant, Admission, NodeError, NodeRuntime},
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
pub struct SwitchoverReceipt {
    pub request_id: String,
    pub operation_id: String,
    pub state: String,
    pub generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SwitchoverError {
    InvalidInput,
    Conflict,
    BlockedUncertain,
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
            return match journal.submit(
                &self.spec.request_id,
                &self.spec.operation_id,
                &self.spec.digest,
            ) {
                Ok(receipt) => {
                    self.old.node.quarantine();
                    Ok(SwitchoverReceipt {
                        request_id: receipt.request_id,
                        operation_id: receipt.operation_id,
                        state: receipt.state,
                        generation: self.routes.active().map_or(0, |route| route.generation()),
                    })
                }
                Err(JournalError::Conflict) => Err(SwitchoverError::Conflict),
                Err(_) => Err(SwitchoverError::Journal),
            };
        }
        self.validate_spec()?;
        if let Err(error) = journal.submit(
            &self.spec.request_id,
            &self.spec.operation_id,
            &self.spec.digest,
        ) {
            if matches!(error, JournalError::Uncertain) {
                self.old.node.quarantine();
            }
            return Err(match error {
                JournalError::Conflict => SwitchoverError::Conflict,
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
            generation: self.spec.new_generation,
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
