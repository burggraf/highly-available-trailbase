use serde::de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt;
use std::path::Path;

pub const CONFIG_LIMIT: usize = 64 * 1024;
const SUPPORTED_SCHEMA_VERSION: u8 = 1;
const MAX_NODES: usize = 64;
const MAX_DATABASES: usize = 64;
const MAX_ENDPOINT_LENGTH: usize = 256;
const MAX_PATH_LENGTH: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    schema_version: u8,
    cluster_id: String,
    primary: String,
    state_dir: String,
    replica_reads: bool,
    required_databases: Vec<String>,
    nodes: Vec<NodeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    id: String,
    endpoint: String,
    data_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    TooLarge,
    InvalidJson(String),
    UnsupportedSchemaVersion(u8),
    InvalidValue(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "configuration exceeds {} bytes", CONFIG_LIMIT),
            Self::InvalidJson(error) => write!(f, "invalid configuration JSON: {error}"),
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported configuration schema version {version}")
            }
            Self::InvalidValue(value) => write!(f, "invalid configuration {value}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u8,
    cluster_id: String,
    primary: String,
    state_dir: String,
    replica_reads: bool,
    required_databases: Vec<String>,
    nodes: Vec<RawNodeConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNodeConfig {
    id: String,
    endpoint: String,
    data_dir: String,
}

impl Config {
    pub fn from_json(input: &str) -> Result<Self, ConfigError> {
        if input.len() > CONFIG_LIMIT {
            return Err(ConfigError::TooLarge);
        }
        reject_duplicate_keys(input)?;
        let raw: RawConfig = serde_json::from_str(input)
            .map_err(|error| ConfigError::InvalidJson(error.to_string()))?;
        if raw.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedSchemaVersion(raw.schema_version));
        }
        if !is_uuid(&raw.cluster_id) {
            return Err(ConfigError::InvalidValue("cluster_id"));
        }
        if raw.replica_reads {
            return Err(ConfigError::InvalidValue(
                "replica_reads: V1 requires false",
            ));
        }
        if !valid_persistent_path(&raw.state_dir) {
            return Err(ConfigError::InvalidValue("state_dir"));
        }
        if raw.nodes.is_empty() || raw.nodes.len() > MAX_NODES {
            return Err(ConfigError::InvalidValue("nodes"));
        }
        if raw.required_databases.is_empty() || raw.required_databases.len() > MAX_DATABASES {
            return Err(ConfigError::InvalidValue("required_databases"));
        }

        let mut node_ids = HashSet::new();
        let mut endpoints = HashSet::new();
        let mut data_dirs = HashSet::new();
        let mut nodes = Vec::with_capacity(raw.nodes.len());
        for node in raw.nodes {
            if !valid_name(&node.id) || !node_ids.insert(node.id.clone()) {
                return Err(ConfigError::InvalidValue("node ids"));
            }
            if !valid_endpoint(&node.endpoint) || !endpoints.insert(node.endpoint.clone()) {
                return Err(ConfigError::InvalidValue("node endpoint"));
            }
            if !valid_persistent_path(&node.data_dir) || !data_dirs.insert(node.data_dir.clone()) {
                return Err(ConfigError::InvalidValue("node data_dir"));
            }
            nodes.push(NodeConfig {
                id: node.id,
                endpoint: node.endpoint,
                data_dir: node.data_dir,
            });
        }
        if !node_ids.contains(&raw.primary) {
            return Err(ConfigError::InvalidValue("primary"));
        }

        let mut databases = HashSet::new();
        if raw
            .required_databases
            .iter()
            .any(|name| !valid_name(name) || name == "logs" || !databases.insert(name.clone()))
            || !databases.contains("main")
            || !databases.contains("session")
        {
            return Err(ConfigError::InvalidValue("required_databases"));
        }

        Ok(Self {
            schema_version: raw.schema_version,
            cluster_id: raw.cluster_id,
            primary: raw.primary,
            state_dir: raw.state_dir,
            replica_reads: raw.replica_reads,
            required_databases: raw.required_databases,
            nodes,
        })
    }

    pub fn schema_version(&self) -> u8 {
        self.schema_version
    }

    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub fn primary_node_id(&self) -> &str {
        &self.primary
    }

    pub fn state_dir(&self) -> &str {
        &self.state_dir
    }

    pub fn replica_reads(&self) -> bool {
        self.replica_reads
    }

    pub fn required_databases(&self) -> &[String] {
        &self.required_databases
    }

    pub fn nodes(&self) -> &[NodeConfig] {
        &self.nodes
    }

    pub fn primary_node(&self) -> &NodeConfig {
        self.node(&self.primary).expect("validated primary node")
    }

    pub fn node(&self, id: &str) -> Option<&NodeConfig> {
        self.nodes.iter().find(|node| node.id == id)
    }
}

impl NodeConfig {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn data_dir(&self) -> &str {
        &self.data_dir
    }
}

fn valid_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_endpoint(value: &str) -> bool {
    if value.len() > MAX_ENDPOINT_LENGTH {
        return false;
    }
    let Some((scheme, authority)) = value.split_once("://") else {
        return false;
    };
    if scheme != "http" && scheme != "https" {
        return false;
    }
    if authority.is_empty()
        || authority.contains(['/', '?', '#', ' ', '\\', '@', '%'])
        || authority.matches(':').count() != 1
    {
        return false;
    }
    let Some((host, port)) = authority.split_once(':') else {
        return false;
    };
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(port) if port != 0)
}

fn valid_persistent_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && value.len() <= MAX_PATH_LENGTH
        && !value.contains('\0')
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && (value == "/var/lib/hat" || value.starts_with("/var/lib/hat/"))
}

pub(crate) fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

pub(crate) fn reject_duplicate_keys(input: &str) -> Result<(), ConfigError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    DuplicateKeyCheck
        .deserialize(&mut deserializer)
        .map_err(|error| ConfigError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ConfigError::InvalidJson(error.to_string()))
}

struct DuplicateKeyCheck;

impl<'de> DeserializeSeed<'de> for DuplicateKeyCheck {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateKeyCheck {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(DuplicateKeyCheck)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateKeyCheck)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> &'static str {
        r#"{
            "schema_version": 1,
            "cluster_id": "00000000-0000-4000-8000-000000000001",
            "primary": "node-a",
            "state_dir": "/var/lib/hat/controller",
            "replica_reads": false,
            "required_databases": ["main", "session", "aux"],
            "nodes": [
                {"id": "node-a", "endpoint": "http://node-a.internal:4000", "data_dir": "/var/lib/hat/node-a"},
                {"id": "node-b", "endpoint": "http://node-b.internal:4000", "data_dir": "/var/lib/hat/node-b"}
            ]
        }"#
    }

    #[test]
    fn accepts_the_v1_configuration_shape() {
        let config = Config::from_json(valid_config()).expect("valid config");
        assert_eq!(config.primary_node_id(), "node-a");
        assert_eq!(config.required_databases(), &["main", "session", "aux"]);
    }

    #[test]
    fn rejects_duplicate_node_ids() {
        let config = valid_config().replace(
            "{\"id\": \"node-b\", \"endpoint\": \"http://node-b.internal:4000\", \"data_dir\": \"/var/lib/hat/node-b\"}",
            "{\"id\": \"node-a\", \"endpoint\": \"http://node-b.internal:4000\", \"data_dir\": \"/var/lib/hat/node-b\"}",
        );
        assert!(Config::from_json(&config).is_err());
    }

    #[test]
    fn rejects_unknown_primary() {
        let config = valid_config().replace("\"primary\": \"node-a\"", "\"primary\": \"node-z\"");
        assert!(Config::from_json(&config).is_err());
    }

    #[test]
    fn rejects_relative_traversal_and_unsupported_paths() {
        for replacement in [
            (
                "\"state_dir\": \"/var/lib/hat/controller\"",
                "\"state_dir\": \"./controller\"",
            ),
            (
                "\"data_dir\": \"/var/lib/hat/node-a\"",
                "\"data_dir\": \"/tmp/node-a\"",
            ),
            (
                "\"data_dir\": \"/var/lib/hat/node-a\"",
                "\"data_dir\": \"/var/lib/hat/../node-a\"",
            ),
        ] {
            let config = valid_config().replace(replacement.0, replacement.1);
            assert!(
                Config::from_json(&config).is_err(),
                "accepted {}",
                replacement.1
            );
        }
    }

    #[test]
    fn rejects_missing_or_local_database_inventory() {
        for replacement in [("\"session\", ", ""), ("\"aux\"", "\"logs\"")] {
            let config = valid_config().replace(replacement.0, replacement.1);
            assert!(Config::from_json(&config).is_err());
        }
    }

    #[test]
    fn rejects_incompatible_schema_version() {
        let config = valid_config().replace("\"schema_version\": 1", "\"schema_version\": 2");
        assert!(Config::from_json(&config).is_err());
    }

    #[test]
    fn rejects_requested_replica_reads() {
        let config = valid_config().replace("\"replica_reads\": false", "\"replica_reads\": true");
        assert!(Config::from_json(&config).is_err());
    }

    #[test]
    fn rejects_invalid_endpoints_and_duplicate_json_keys() {
        for endpoint in [
            "http://user@node-a.internal:4000",
            "http://node-a.internal:0",
            "http://node-a.internal:not-a-port",
            "http://node_a.internal:4000",
        ] {
            let config = valid_config().replace("http://node-a.internal:4000", endpoint);
            assert!(Config::from_json(&config).is_err(), "accepted {endpoint}");
        }

        let unknown = valid_config().replace(
            "\"replica_reads\": false",
            "\"replica_reads\": false, \"future\": true",
        );
        assert!(Config::from_json(&unknown).is_err());

        let duplicate = valid_config().replace(
            "\"schema_version\": 1",
            "\"schema_version\": 1, \"schema_version\": 1",
        );
        assert!(Config::from_json(&duplicate).is_err());
    }
}
