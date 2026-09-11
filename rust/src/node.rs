use crate::config::is_uuid;
use std::collections::{HashMap, HashSet};
use std::process::{Child, Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Primary,
    Standby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Closed,
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationGrant {
    pub cluster_id: String,
    pub node_id: String,
    pub incarnation: String,
    pub writer_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeState {
    cluster_id: String,
    node_id: String,
    incarnation: String,
    role: NodeRole,
    admission: Admission,
    writer_epoch: Option<u64>,
    revision: u64,
    used_incarnations: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    InvalidIdentity,
    WrongCluster,
    WrongNode,
    WrongIncarnation,
    StandbyActivation,
    MissingEpoch,
    SameIncarnation,
    ReusedIncarnation,
    ChildLimit,
}

impl NodeState {
    pub fn new(
        cluster_id: &str,
        node_id: &str,
        incarnation: &str,
        role: NodeRole,
    ) -> Result<Self, NodeError> {
        if !is_uuid(cluster_id) || !is_uuid(incarnation) || node_id.is_empty() {
            return Err(NodeError::InvalidIdentity);
        }
        Ok(Self {
            cluster_id: cluster_id.to_owned(),
            node_id: node_id.to_owned(),
            incarnation: incarnation.to_owned(),
            role,
            admission: Admission::Closed,
            writer_epoch: None,
            revision: 0,
            used_incarnations: HashSet::from([incarnation.to_owned()]),
        })
    }

    pub fn activate(&mut self, grant: &ActivationGrant) -> Result<(), NodeError> {
        if grant.cluster_id != self.cluster_id {
            return Err(NodeError::WrongCluster);
        }
        if grant.node_id != self.node_id {
            return Err(NodeError::WrongNode);
        }
        if grant.incarnation != self.incarnation {
            return Err(NodeError::WrongIncarnation);
        }
        if self.role == NodeRole::Standby {
            return Err(NodeError::StandbyActivation);
        }
        if grant.writer_epoch == 0 {
            return Err(NodeError::MissingEpoch);
        }
        self.writer_epoch = Some(grant.writer_epoch);
        self.admission = Admission::Open;
        self.revision += 1;
        Ok(())
    }

    pub fn restart(&mut self, incarnation: &str) -> Result<(), NodeError> {
        if !is_uuid(incarnation) {
            return Err(NodeError::InvalidIdentity);
        }
        if incarnation == self.incarnation {
            return Err(NodeError::SameIncarnation);
        }
        if self.used_incarnations.contains(incarnation) {
            return Err(NodeError::ReusedIncarnation);
        }
        self.used_incarnations.insert(incarnation.to_owned());
        self.incarnation = incarnation.to_owned();
        self.writer_epoch = None;
        self.admission = Admission::Closed;
        self.revision += 1;
        Ok(())
    }

    pub fn close_admission(&mut self) {
        self.admission = Admission::Closed;
    }

    pub fn admission(&self) -> Admission {
        self.admission
    }

    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    pub fn writer_epoch(&self) -> Option<u64> {
        self.writer_epoch
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildState {
    Running,
    Exited(Option<i32>),
    Missing,
}

const MAX_CHILDREN: usize = 2;

pub struct ChildSupervisor {
    children: HashMap<String, Child>,
}

impl Default for ChildSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl ChildSupervisor {
    pub fn new() -> Self {
        Self {
            children: HashMap::new(),
        }
    }

    pub fn spawn(&mut self, name: &str, command: &mut Command) -> std::io::Result<()> {
        if self.children.contains_key(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "child name already owned",
            ));
        }
        if self.children.len() >= MAX_CHILDREN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "child limit reached",
            ));
        }
        let child = command.spawn()?;
        self.children.insert(name.to_owned(), child);
        Ok(())
    }

    pub fn state(&mut self, name: &str) -> std::io::Result<ChildState> {
        let Some(child) = self.children.get_mut(name) else {
            return Ok(ChildState::Missing);
        };
        match child.try_wait()? {
            Some(status) => {
                let state = ChildState::Exited(status.code());
                self.children.remove(name);
                Ok(state)
            }
            None => Ok(ChildState::Running),
        }
    }

    pub fn stop(&mut self, name: &str) -> std::io::Result<ChildState> {
        let Some(mut child) = self.children.remove(name) else {
            return Ok(ChildState::Missing);
        };
        if child.try_wait()?.is_none() {
            let _ = child.kill();
        }
        Ok(ChildState::Exited(child.wait()?.code()))
    }
}

impl Drop for ChildSupervisor {
    fn drop(&mut self) {
        for child in self.children.values_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub struct NodeRuntime {
    pub node: NodeState,
    pub children: ChildSupervisor,
}

impl NodeRuntime {
    pub fn new(node: NodeState) -> Self {
        Self {
            node,
            children: ChildSupervisor::new(),
        }
    }

    pub fn stop_child(&mut self, name: &str) -> std::io::Result<ChildState> {
        self.node.close_admission();
        self.children.stop(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "11111111-1111-4111-8111-111111111111";
    const INCARNATION: &str = "22222222-2222-4222-8222-222222222222";

    fn grant(incarnation: &str) -> ActivationGrant {
        ActivationGrant {
            cluster_id: CLUSTER.into(),
            node_id: "node-a".into(),
            incarnation: incarnation.into(),
            writer_epoch: 4,
        }
    }

    #[test]
    fn starts_closed_and_requires_exact_activation_identity() {
        let mut node = NodeState::new(CLUSTER, "node-a", INCARNATION, NodeRole::Primary).unwrap();
        assert_eq!(node.admission(), Admission::Closed);
        assert_eq!(
            node.activate(&grant("33333333-3333-4333-8333-333333333333")),
            Err(NodeError::WrongIncarnation)
        );
        assert_eq!(node.admission(), Admission::Closed);
        node.activate(&grant(INCARNATION)).unwrap();
        assert_eq!(node.admission(), Admission::Open);
        assert_eq!(node.writer_epoch(), Some(4));
    }

    #[test]
    fn restart_closes_admission_and_invalidates_old_grant() {
        let mut node = NodeState::new(CLUSTER, "node-a", INCARNATION, NodeRole::Primary).unwrap();
        node.activate(&grant(INCARNATION)).unwrap();
        node.restart("33333333-3333-4333-8333-333333333333")
            .unwrap();
        assert_eq!(node.admission(), Admission::Closed);
        assert_eq!(
            node.activate(&grant(INCARNATION)),
            Err(NodeError::WrongIncarnation)
        );
        assert_eq!(
            node.restart("33333333-3333-4333-8333-333333333333"),
            Err(NodeError::SameIncarnation)
        );
        node.restart("44444444-4444-4444-8444-444444444444")
            .unwrap();
        assert_eq!(
            node.restart("33333333-3333-4333-8333-333333333333"),
            Err(NodeError::ReusedIncarnation)
        );
    }

    #[test]
    fn stopping_a_child_closes_node_admission() {
        let node = NodeState::new(CLUSTER, "node-a", INCARNATION, NodeRole::Primary).unwrap();
        let mut runtime = NodeRuntime::new(node);
        runtime
            .children
            .spawn("follower", Command::new("sh").arg("-c").arg("sleep 10"))
            .unwrap();
        runtime.stop_child("follower").unwrap();
        assert_eq!(runtime.node.admission(), Admission::Closed);
    }

    #[test]
    fn child_exit_is_observable_and_stop_reaps_owned_child() {
        let mut supervisor = ChildSupervisor::new();
        supervisor
            .spawn("follower", Command::new("sh").arg("-c").arg("exit 7"))
            .unwrap();
        let mut state = ChildState::Running;
        for _ in 0..100 {
            state = supervisor.state("follower").unwrap();
            if state != ChildState::Running {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(state, ChildState::Exited(Some(7)));
        supervisor
            .spawn("uploader", Command::new("sh").arg("-c").arg("sleep 10"))
            .unwrap();
        assert!(matches!(
            supervisor.stop("uploader").unwrap(),
            ChildState::Exited(_)
        ));
    }
}
