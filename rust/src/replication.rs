use crate::config::Config;
use crate::node::NodeRole;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseReplication {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicationConfig {
    pub role: NodeRole,
    pub databases: Vec<DatabaseReplication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    None,
    Follower,
    Uploader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseObservation {
    pub process_alive: Option<bool>,
    pub position: Option<u64>,
    pub age_seconds: Option<u64>,
    pub recoverable: Option<bool>,
    pub error: Option<String>,
}

impl DatabaseObservation {
    pub fn unknown() -> Self {
        Self {
            process_alive: None,
            position: None,
            age_seconds: None,
            recoverable: None,
            error: None,
        }
    }

    pub fn healthy(&self) -> bool {
        self.process_alive == Some(true)
            && self.position.is_some()
            && self.age_seconds.is_some()
            && self.recoverable == Some(true)
            && self.error.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationError {
    InvalidDatabase,
    ConflictingOwner,
}

pub fn config(config: &Config, role: NodeRole) -> Result<ReplicationConfig, ReplicationError> {
    let databases = config
        .required_databases()
        .iter()
        .map(|name| {
            if name == "logs" {
                Err(ReplicationError::InvalidDatabase)
            } else {
                Ok(DatabaseReplication { name: name.clone() })
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ReplicationConfig { role, databases })
}

pub struct ReplicationRuntime {
    config: ReplicationConfig,
    owners: HashMap<String, Ownership>,
    observations: HashMap<String, DatabaseObservation>,
}

impl ReplicationRuntime {
    pub fn new(config: ReplicationConfig) -> Self {
        let owners = config
            .databases
            .iter()
            .map(|database| (database.name.clone(), Ownership::None))
            .collect();
        let observations = config
            .databases
            .iter()
            .map(|database| (database.name.clone(), DatabaseObservation::unknown()))
            .collect();
        Self {
            config,
            owners,
            observations,
        }
    }

    pub fn acquire(&mut self, database: &str, owner: Ownership) -> Result<(), ReplicationError> {
        if owner == Ownership::None || !self.owners.contains_key(database) {
            return Err(ReplicationError::InvalidDatabase);
        }
        let current = self.owners[database];
        if current != Ownership::None && current != owner {
            return Err(ReplicationError::ConflictingOwner);
        }
        self.owners.insert(database.to_owned(), owner);
        Ok(())
    }

    pub fn owner(&self, database: &str) -> Option<Ownership> {
        self.owners.get(database).copied()
    }

    pub fn observe(
        &mut self,
        database: &str,
        observation: DatabaseObservation,
    ) -> Result<(), ReplicationError> {
        if !self.observations.contains_key(database) {
            return Err(ReplicationError::InvalidDatabase);
        }
        self.observations.insert(database.to_owned(), observation);
        Ok(())
    }

    pub fn observation(&self, database: &str) -> Option<&DatabaseObservation> {
        self.observations.get(database)
    }

    pub fn config(&self) -> &ReplicationConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config_json(databases: &str) -> Config {
        Config::from_json(&format!(
            r#"{{"schema_version":1,"cluster_id":"11111111-1111-4111-8111-111111111111","primary":"node-a","controller_node":"node-a","state_dir":"/var/lib/hat/state","replica_reads":false,"required_databases":[{databases}],"nodes":[{{"id":"node-a","endpoint":"http://127.0.0.1:18080","data_dir":"/var/lib/hat/node-a"}}]}}"#
        ))
        .unwrap()
    }

    #[test]
    fn config_uses_declared_databases_and_role_only() {
        let replication = config(
            &config_json("\"main\",\"session\",\"aux\""),
            NodeRole::Standby,
        )
        .unwrap();
        assert_eq!(replication.role, NodeRole::Standby);
        assert_eq!(
            replication
                .databases
                .iter()
                .map(|db| db.name.as_str())
                .collect::<Vec<_>>(),
            ["main", "session", "aux"]
        );
    }

    #[test]
    fn ownership_prevents_follower_and_uploader_overlap() {
        let mut runtime = ReplicationRuntime::new(
            config(&config_json("\"main\",\"session\""), NodeRole::Primary).unwrap(),
        );
        runtime.acquire("main", Ownership::Uploader).unwrap();
        assert_eq!(
            runtime.acquire("main", Ownership::Follower),
            Err(ReplicationError::ConflictingOwner)
        );
    }

    #[test]
    fn unknown_observation_is_not_healthy() {
        let runtime = ReplicationRuntime::new(
            config(&config_json("\"main\",\"session\""), NodeRole::Standby).unwrap(),
        );
        assert!(!runtime.observation("main").unwrap().healthy());
    }
}
