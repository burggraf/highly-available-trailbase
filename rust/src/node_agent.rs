use crate::{
    config::{is_uuid, reject_duplicate_keys},
    controller::ActionCommand,
    node::{Admission, NodeRole, NodeState},
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: u8 = 1;
const WIRE_LIMIT: usize = 8 * 1024;
const DIGEST_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeActionCommand {
    pub cluster_id: String,
    pub controller_node_id: String,
    pub node_id: String,
    pub incarnation: String,
    pub request_id: String,
    pub operation_id: String,
    pub digest: String,
    pub kind: String,
    pub expected_generation: String,
    pub expected_role: String,
    pub expected_admission: String,
    pub accept_possible_loss: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeObservation {
    pub cluster_id: String,
    pub node_id: String,
    pub incarnation: String,
    pub route_generation: Option<String>,
    pub role: String,
    pub admission: String,
    pub health: String,
    pub replication: String,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeBoundaryError {
    TooLarge,
    InvalidWire,
    UnsupportedSchema,
    InvalidField(&'static str),
    DigestMismatch,
    ClusterMismatch,
    NodeMismatch,
    IncarnationMismatch,
    UnknownGeneration,
    GenerationMismatch,
    RoleMismatch,
    AdmissionMismatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireActionCommand {
    schema_version: u8,
    cluster_id: String,
    controller_node_id: String,
    node_id: String,
    incarnation: String,
    request_id: String,
    operation_id: String,
    digest: String,
    kind: String,
    expected_generation: String,
    expected_role: String,
    expected_admission: String,
    accept_possible_loss: bool,
}

#[derive(Serialize)]
struct EncodedActionCommand<'a> {
    schema_version: u8,
    cluster_id: &'a str,
    controller_node_id: &'a str,
    node_id: &'a str,
    incarnation: &'a str,
    request_id: &'a str,
    operation_id: &'a str,
    digest: &'a str,
    kind: &'a str,
    expected_generation: &'a str,
    expected_role: &'a str,
    expected_admission: &'a str,
    accept_possible_loss: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservation {
    schema_version: u8,
    cluster_id: String,
    node_id: String,
    incarnation: String,
    route_generation: Option<String>,
    role: String,
    admission: String,
    health: String,
    replication: String,
    revision: u64,
}

#[derive(Serialize)]
struct EncodedObservation<'a> {
    schema_version: u8,
    cluster_id: &'a str,
    node_id: &'a str,
    incarnation: &'a str,
    route_generation: Option<&'a str>,
    role: &'a str,
    admission: &'a str,
    health: &'a str,
    replication: &'a str,
    revision: u64,
}

impl NodeActionCommand {
    pub fn from_controller(
        command: &ActionCommand,
        incarnation: &str,
    ) -> Result<Self, NodeBoundaryError> {
        if !command.digest_matches() {
            return Err(NodeBoundaryError::DigestMismatch);
        }
        let command = Self {
            cluster_id: command.cluster_id.clone(),
            controller_node_id: command.controller_node_id.clone(),
            node_id: command.target_node_id.clone(),
            incarnation: incarnation.to_owned(),
            request_id: command.request_id.clone(),
            operation_id: command.operation_id.clone(),
            digest: command.digest.clone(),
            kind: command.kind.clone(),
            expected_generation: command.expected_generation.clone(),
            expected_role: command.expected_role.clone(),
            expected_admission: command.expected_admission.clone(),
            accept_possible_loss: command.accept_possible_loss,
        };
        command.validate_fields()?;
        Ok(command)
    }

    pub fn from_wire_json(input: &str) -> Result<Self, NodeBoundaryError> {
        if input.len() > WIRE_LIMIT {
            return Err(NodeBoundaryError::TooLarge);
        }
        reject_duplicate_keys(input).map_err(|_| NodeBoundaryError::InvalidWire)?;
        let raw: WireActionCommand =
            serde_json::from_str(input).map_err(|_| NodeBoundaryError::InvalidWire)?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(NodeBoundaryError::UnsupportedSchema);
        }
        let command = Self {
            cluster_id: raw.cluster_id,
            controller_node_id: raw.controller_node_id,
            node_id: raw.node_id,
            incarnation: raw.incarnation,
            request_id: raw.request_id,
            operation_id: raw.operation_id,
            digest: raw.digest,
            kind: raw.kind,
            expected_generation: raw.expected_generation,
            expected_role: raw.expected_role,
            expected_admission: raw.expected_admission,
            accept_possible_loss: raw.accept_possible_loss,
        };
        command.validate_fields()?;
        if !command.to_action_command().digest_matches() {
            return Err(NodeBoundaryError::DigestMismatch);
        }
        Ok(command)
    }

    pub fn to_wire_json(&self) -> String {
        serde_json::to_string(&EncodedActionCommand {
            schema_version: SCHEMA_VERSION,
            cluster_id: &self.cluster_id,
            controller_node_id: &self.controller_node_id,
            node_id: &self.node_id,
            incarnation: &self.incarnation,
            request_id: &self.request_id,
            operation_id: &self.operation_id,
            digest: &self.digest,
            kind: &self.kind,
            expected_generation: &self.expected_generation,
            expected_role: &self.expected_role,
            expected_admission: &self.expected_admission,
            accept_possible_loss: self.accept_possible_loss,
        })
        .expect("node action encoding cannot fail")
    }

    pub fn to_action_command(&self) -> ActionCommand {
        ActionCommand {
            cluster_id: self.cluster_id.clone(),
            controller_node_id: self.controller_node_id.clone(),
            request_id: self.request_id.clone(),
            operation_id: self.operation_id.clone(),
            digest: self.digest.clone(),
            kind: self.kind.clone(),
            target_node_id: self.node_id.clone(),
            expected_generation: self.expected_generation.clone(),
            expected_role: self.expected_role.clone(),
            expected_admission: self.expected_admission.clone(),
            accept_possible_loss: self.accept_possible_loss,
        }
    }

    pub fn validate_against(&self, observation: &NodeObservation) -> Result<(), NodeBoundaryError> {
        self.validate_fields()?;
        observation.validate_fields()?;
        if self.cluster_id != observation.cluster_id {
            return Err(NodeBoundaryError::ClusterMismatch);
        }
        if self.node_id != observation.node_id {
            return Err(NodeBoundaryError::NodeMismatch);
        }
        if self.incarnation != observation.incarnation {
            return Err(NodeBoundaryError::IncarnationMismatch);
        }
        if !self.to_action_command().digest_matches() {
            return Err(NodeBoundaryError::DigestMismatch);
        }
        let Some(generation) = observation.route_generation.as_deref() else {
            return Err(NodeBoundaryError::UnknownGeneration);
        };
        if generation != self.expected_generation {
            return Err(NodeBoundaryError::GenerationMismatch);
        }
        if self.expected_role != observation.role {
            return Err(NodeBoundaryError::RoleMismatch);
        }
        if self.expected_admission != observation.admission {
            return Err(NodeBoundaryError::AdmissionMismatch);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), NodeBoundaryError> {
        if !is_uuid(&self.cluster_id) {
            return Err(NodeBoundaryError::InvalidField("cluster_id"));
        }
        if !valid_id(&self.controller_node_id, 32) {
            return Err(NodeBoundaryError::InvalidField("controller_node_id"));
        }
        if !valid_id(&self.node_id, 32) {
            return Err(NodeBoundaryError::InvalidField("node_id"));
        }
        if !is_uuid(&self.incarnation) {
            return Err(NodeBoundaryError::InvalidField("incarnation"));
        }
        if !valid_id(&self.request_id, 128) {
            return Err(NodeBoundaryError::InvalidField("request_id"));
        }
        if !valid_id(&self.operation_id, 128) {
            return Err(NodeBoundaryError::InvalidField("operation_id"));
        }
        if !valid_digest(&self.digest) {
            return Err(NodeBoundaryError::InvalidField("digest"));
        }
        if !matches!(
            self.kind.as_str(),
            "failover" | "restart" | "shutdown" | "rejoin"
        ) {
            return Err(NodeBoundaryError::InvalidField("kind"));
        }
        if !valid_generation(&self.expected_generation) {
            return Err(NodeBoundaryError::InvalidField("expected_generation"));
        }
        if !matches!(self.expected_role.as_str(), "primary" | "standby") {
            return Err(NodeBoundaryError::InvalidField("expected_role"));
        }
        if !matches!(
            self.expected_admission.as_str(),
            "open" | "closed" | "unknown"
        ) {
            return Err(NodeBoundaryError::InvalidField("expected_admission"));
        }
        Ok(())
    }
}

impl NodeObservation {
    pub fn from_node(
        node: &NodeState,
        route_generation: Option<u64>,
    ) -> Result<Self, NodeBoundaryError> {
        let observation = Self {
            cluster_id: node.cluster_id().to_owned(),
            node_id: node.node_id().to_owned(),
            incarnation: node.incarnation().to_owned(),
            route_generation: route_generation.map(|value| value.to_string()),
            role: match node.role() {
                NodeRole::Primary => "primary",
                NodeRole::Standby => "standby",
            }
            .into(),
            admission: match node.admission() {
                Admission::Open => "open",
                Admission::Closed => "closed",
            }
            .into(),
            health: "unknown".into(),
            replication: "unknown".into(),
            revision: node.revision(),
        };
        observation.validate_fields()?;
        Ok(observation)
    }

    pub fn from_wire_json(input: &str) -> Result<Self, NodeBoundaryError> {
        if input.len() > WIRE_LIMIT {
            return Err(NodeBoundaryError::TooLarge);
        }
        reject_duplicate_keys(input).map_err(|_| NodeBoundaryError::InvalidWire)?;
        let raw: WireObservation =
            serde_json::from_str(input).map_err(|_| NodeBoundaryError::InvalidWire)?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(NodeBoundaryError::UnsupportedSchema);
        }
        let observation = Self {
            cluster_id: raw.cluster_id,
            node_id: raw.node_id,
            incarnation: raw.incarnation,
            route_generation: raw.route_generation,
            role: raw.role,
            admission: raw.admission,
            health: raw.health,
            replication: raw.replication,
            revision: raw.revision,
        };
        observation.validate_fields()?;
        Ok(observation)
    }

    pub fn to_wire_json(&self) -> String {
        serde_json::to_string(&EncodedObservation {
            schema_version: SCHEMA_VERSION,
            cluster_id: &self.cluster_id,
            node_id: &self.node_id,
            incarnation: &self.incarnation,
            route_generation: self.route_generation.as_deref(),
            role: &self.role,
            admission: &self.admission,
            health: &self.health,
            replication: &self.replication,
            revision: self.revision,
        })
        .expect("node observation encoding cannot fail")
    }

    fn validate_fields(&self) -> Result<(), NodeBoundaryError> {
        if !is_uuid(&self.cluster_id) {
            return Err(NodeBoundaryError::InvalidField("cluster_id"));
        }
        if !valid_id(&self.node_id, 32) {
            return Err(NodeBoundaryError::InvalidField("node_id"));
        }
        if !is_uuid(&self.incarnation) {
            return Err(NodeBoundaryError::InvalidField("incarnation"));
        }
        if let Some(generation) = &self.route_generation {
            if !valid_generation(generation) {
                return Err(NodeBoundaryError::InvalidField("route_generation"));
            }
        }
        if !matches!(self.role.as_str(), "primary" | "standby") {
            return Err(NodeBoundaryError::InvalidField("role"));
        }
        if !matches!(self.admission.as_str(), "open" | "closed") {
            return Err(NodeBoundaryError::InvalidField("admission"));
        }
        if !matches!(
            self.health.as_str(),
            "unknown" | "healthy" | "stale" | "unavailable"
        ) {
            return Err(NodeBoundaryError::InvalidField("health"));
        }
        if !matches!(
            self.replication.as_str(),
            "unknown" | "streaming" | "caught_up" | "stale" | "error"
        ) {
            return Err(NodeBoundaryError::InvalidField("replication"));
        }
        Ok(())
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_digest(value: &str) -> bool {
    value.len() == DIGEST_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_generation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "00000000-0000-4000-8000-000000000001";
    const INCARNATION: &str = "00000000-0000-4000-8000-000000000002";

    fn node() -> NodeState {
        NodeState::new(CLUSTER, "node-a", INCARNATION, NodeRole::Standby).unwrap()
    }

    fn action() -> ActionCommand {
        let mut command = ActionCommand {
            cluster_id: CLUSTER.into(),
            controller_node_id: "node-controller".into(),
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            digest: String::new(),
            kind: "restart".into(),
            target_node_id: "node-a".into(),
            expected_generation: "3".into(),
            expected_role: "standby".into(),
            expected_admission: "closed".into(),
            accept_possible_loss: false,
        };
        command.digest = command.derived_digest();
        command
    }

    #[test]
    fn observation_round_trips_and_unknown_generation_refuses_action() {
        let observation = NodeObservation::from_node(&node(), None).unwrap();
        let decoded = NodeObservation::from_wire_json(&observation.to_wire_json()).unwrap();
        assert_eq!(decoded, observation);
        let command = NodeActionCommand::from_controller(&action(), INCARNATION).unwrap();
        assert_eq!(
            command.validate_against(&decoded),
            Err(NodeBoundaryError::UnknownGeneration)
        );
    }

    #[test]
    fn valid_command_binds_exact_observation_and_round_trips() {
        let observation = NodeObservation::from_node(&node(), Some(3)).unwrap();
        let command = NodeActionCommand::from_controller(&action(), INCARNATION).unwrap();
        let decoded = NodeActionCommand::from_wire_json(&command.to_wire_json()).unwrap();
        assert_eq!(decoded, command);
        assert_eq!(decoded.validate_against(&observation), Ok(()));
    }

    #[test]
    fn command_refuses_stale_or_mismatched_state_and_digest() {
        let observation = NodeObservation::from_node(&node(), Some(4)).unwrap();
        let command = NodeActionCommand::from_controller(&action(), INCARNATION).unwrap();
        assert_eq!(
            command.validate_against(&observation),
            Err(NodeBoundaryError::GenerationMismatch)
        );

        let mut wrong = command.clone();
        wrong.incarnation = "00000000-0000-4000-8000-000000000003".into();
        assert_eq!(
            wrong.validate_against(&observation),
            Err(NodeBoundaryError::IncarnationMismatch)
        );

        let mut tampered = command;
        tampered.kind = "shutdown".into();
        assert_eq!(
            tampered.validate_against(&NodeObservation::from_node(&node(), Some(3)).unwrap()),
            Err(NodeBoundaryError::DigestMismatch)
        );
    }

    #[test]
    fn observation_constructor_refuses_malformed_local_state() {
        let malformed =
            NodeState::new(CLUSTER, "node with spaces", INCARNATION, NodeRole::Standby).unwrap();
        assert_eq!(
            NodeObservation::from_node(&malformed, Some(3)),
            Err(NodeBoundaryError::InvalidField("node_id"))
        );
    }

    #[test]
    fn wire_refuses_unknown_duplicate_and_oversized_input() {
        let observation = NodeObservation::from_node(&node(), Some(3)).unwrap();
        let wire = observation.to_wire_json();
        assert!(
            NodeObservation::from_wire_json(&wire.replacen("}", ",\"extra\":true}", 1)).is_err()
        );
        assert!(NodeObservation::from_wire_json(&wire.replacen(
            "\"node_id\":\"node-a\"",
            "\"node_id\":\"node-a\",\"node_id\":\"node-a\"",
            1
        ))
        .is_err());
        assert_eq!(
            NodeObservation::from_wire_json(&"x".repeat(WIRE_LIMIT + 1)),
            Err(NodeBoundaryError::TooLarge)
        );
    }
}
