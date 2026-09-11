use crate::config::{is_uuid, reject_duplicate_keys, Config, ConfigError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

const ROUTE_LIMIT: usize = 8 * 1024;
const SCHEMA_VERSION: u8 = 1;
const DIGEST_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    schema_version: u8,
    cluster_id: String,
    generation: u64,
    primary_node_id: String,
    writer_epoch: u64,
    primary_incarnation: String,
    release_digest: String,
    config_digest: String,
    endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedTarget {
    pub node_id: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    Missing,
    Rollback,
    Conflict,
    ClusterMismatch,
    UnknownNode,
    InvalidRoute(&'static str),
    InvalidWire(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "no active route",
            Self::Rollback => "route generation rollback",
            Self::Conflict => "conflicting route at the same generation",
            Self::ClusterMismatch => "route belongs to another cluster",
            Self::UnknownNode => "route names an unknown node",
            Self::InvalidRoute(value) => value,
            Self::InvalidWire(value) => value,
        })
    }
}

impl std::error::Error for RouteError {}

#[derive(Debug, Clone)]
pub struct RouteTable {
    cluster_id: String,
    endpoints: HashMap<String, String>,
    active: Option<Route>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRoute {
    schema_version: u8,
    cluster_id: String,
    generation: String,
    primary_node_id: String,
    writer_epoch: String,
    primary_incarnation: String,
    release_digest: String,
    config_digest: String,
}

#[derive(Serialize)]
struct EncodedRoute<'a> {
    schema_version: u8,
    cluster_id: &'a str,
    generation: String,
    primary_node_id: &'a str,
    writer_epoch: String,
    primary_incarnation: &'a str,
    release_digest: &'a str,
    config_digest: &'a str,
}

impl Route {
    pub fn from_config(
        config: &Config,
        generation: u64,
        writer_epoch: u64,
        primary_incarnation: &str,
        release_digest: &str,
        config_digest: &str,
    ) -> Result<Self, RouteError> {
        Self::for_node(
            config,
            config.primary_node_id(),
            generation,
            writer_epoch,
            primary_incarnation,
            release_digest,
            config_digest,
        )
    }

    pub fn for_node(
        config: &Config,
        node_id: &str,
        generation: u64,
        writer_epoch: u64,
        primary_incarnation: &str,
        release_digest: &str,
        config_digest: &str,
    ) -> Result<Self, RouteError> {
        let node = config.node(node_id).ok_or(RouteError::UnknownNode)?;
        if !is_uuid(primary_incarnation) {
            return Err(RouteError::InvalidRoute("invalid primary incarnation"));
        }
        if !valid_digest(release_digest) || !valid_digest(config_digest) {
            return Err(RouteError::InvalidRoute("invalid route digest"));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            cluster_id: config.cluster_id().to_owned(),
            generation,
            primary_node_id: node.id().to_owned(),
            writer_epoch,
            primary_incarnation: primary_incarnation.to_owned(),
            release_digest: release_digest.to_owned(),
            config_digest: config_digest.to_owned(),
            endpoint: node.endpoint().to_owned(),
        })
    }

    pub fn from_wire_json(config: &Config, input: &str) -> Result<Self, RouteError> {
        if input.len() > ROUTE_LIMIT {
            return Err(RouteError::InvalidWire("route exceeds size limit".into()));
        }
        reject_duplicate_keys(input).map_err(config_error_to_route)?;
        let raw: WireRoute = serde_json::from_str(input)
            .map_err(|_| RouteError::InvalidWire("invalid route JSON".into()))?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(RouteError::InvalidWire(
                "unsupported route schema version".into(),
            ));
        }
        if raw.cluster_id != config.cluster_id() {
            return Err(RouteError::ClusterMismatch);
        }
        let generation = parse_decimal(&raw.generation, "generation")?;
        let writer_epoch = parse_decimal(&raw.writer_epoch, "writer_epoch")?;
        Self::for_node(
            config,
            &raw.primary_node_id,
            generation,
            writer_epoch,
            &raw.primary_incarnation,
            &raw.release_digest,
            &raw.config_digest,
        )
    }

    pub fn to_wire_json(&self) -> String {
        serde_json::to_string(&EncodedRoute {
            schema_version: self.schema_version,
            cluster_id: &self.cluster_id,
            generation: self.generation.to_string(),
            primary_node_id: &self.primary_node_id,
            writer_epoch: self.writer_epoch.to_string(),
            primary_incarnation: &self.primary_incarnation,
            release_digest: &self.release_digest,
            config_digest: &self.config_digest,
        })
        .expect("route wire encoding cannot fail")
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn writer_epoch(&self) -> u64 {
        self.writer_epoch
    }

    pub fn primary_node_id(&self) -> &str {
        &self.primary_node_id
    }
}

impl RouteTable {
    pub fn new(config: &Config) -> Self {
        Self {
            cluster_id: config.cluster_id().to_owned(),
            endpoints: config
                .nodes()
                .iter()
                .map(|node| (node.id().to_owned(), node.endpoint().to_owned()))
                .collect(),
            active: None,
        }
    }

    pub fn install(&mut self, route: Route) -> Result<(), RouteError> {
        if route.cluster_id != self.cluster_id {
            return Err(RouteError::ClusterMismatch);
        }
        if self.endpoints.get(&route.primary_node_id) != Some(&route.endpoint) {
            return Err(RouteError::UnknownNode);
        }
        let Some(active) = &self.active else {
            self.active = Some(route);
            return Ok(());
        };
        if route.generation < active.generation {
            return Err(RouteError::Rollback);
        }
        if route.generation == active.generation {
            return if route == *active {
                Ok(())
            } else {
                Err(RouteError::Conflict)
            };
        }
        self.active = Some(route);
        Ok(())
    }

    pub fn active(&self) -> Option<&Route> {
        self.active.as_ref()
    }

    pub fn select(&self, _method: &str, _path: &str) -> Result<SelectedTarget, RouteError> {
        let route = self.active.as_ref().ok_or(RouteError::Missing)?;
        Ok(SelectedTarget {
            node_id: route.primary_node_id.clone(),
            endpoint: route.endpoint.clone(),
        })
    }
}

fn config_error_to_route(error: ConfigError) -> RouteError {
    match error {
        ConfigError::TooLarge => RouteError::InvalidWire("route exceeds size limit".into()),
        ConfigError::InvalidJson(_) => RouteError::InvalidWire("invalid route JSON".into()),
        ConfigError::UnsupportedSchemaVersion(_) => {
            RouteError::InvalidWire("unsupported route schema version".into())
        }
        ConfigError::InvalidValue(_) => RouteError::InvalidWire("invalid route JSON".into()),
    }
}

fn parse_decimal(value: &str, field: &'static str) -> Result<u64, RouteError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(RouteError::InvalidRoute(field));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RouteError::InvalidRoute(field));
    }
    value
        .parse::<u64>()
        .map_err(|_| RouteError::InvalidRoute(field))
}

fn valid_digest(value: &str) -> bool {
    value.len() == DIGEST_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: &str = "00000000-0000-4000-8000-000000000001";
    const INCARNATION: &str = "00000000-0000-4000-8000-000000000002";
    const RELEASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONFIG: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn config() -> Config {
        Config::from_json(&format!(
            r#"{{
                "schema_version": 1,
                "cluster_id": "{CLUSTER}",
                "primary": "node-a",
                "state_dir": "/var/lib/hat/controller",
                "replica_reads": false,
                "required_databases": ["main", "session", "aux"],
                "nodes": [
                    {{"id": "node-a", "endpoint": "http://node-a.internal:4000", "data_dir": "/var/lib/hat/node-a"}},
                    {{"id": "node-b", "endpoint": "http://node-b.internal:4000", "data_dir": "/var/lib/hat/node-b"}}
                ]
            }}"#
        ))
        .expect("valid config")
    }

    fn route(config: &Config, generation: u64, node_id: &str) -> Route {
        Route::for_node(config, node_id, generation, 1, INCARNATION, RELEASE, CONFIG)
            .expect("valid route")
    }

    #[test]
    fn route_binds_to_inventory_endpoint_and_wire_generation_is_decimal() {
        let config = config();
        let route = route(&config, u64::MAX, "node-a");
        let wire = route.to_wire_json();
        assert!(wire.contains(r#""generation":"18446744073709551615""#));
        assert!(!wire.contains("endpoint"));

        let parsed = Route::from_wire_json(&config, &wire).expect("wire route");
        let selected = {
            let mut table = RouteTable::new(&config);
            table.install(parsed).expect("install route");
            table.select("GET", "/anything").expect("active route")
        };
        assert_eq!(selected.node_id, "node-a");
        assert_eq!(selected.endpoint, "http://node-a.internal:4000");
    }

    #[test]
    fn every_application_request_selects_the_active_primary() {
        let config = config();
        let mut routes = RouteTable::new(&config);
        routes
            .install(route(&config, 1, "node-a"))
            .expect("install route");

        for (method, path) in [
            ("GET", "/api/records"),
            ("POST", "/api/records"),
            ("GET", "/api/auth/logout"),
            ("GET", "/api/records/subscribe"),
            ("POST", "/_admin/schema"),
            ("PATCH", "/custom/job"),
        ] {
            let selected = routes.select(method, path).expect("active route");
            assert_eq!(selected.node_id, "node-a");
            assert_eq!(selected.endpoint, "http://node-a.internal:4000");
        }
    }

    #[test]
    fn missing_route_refuses_selection() {
        assert!(matches!(
            RouteTable::new(&config()).select("GET", "/anything"),
            Err(RouteError::Missing)
        ));
    }

    #[test]
    fn rollback_and_conflicting_equal_generation_leave_active_route_unchanged() {
        let config = config();
        let mut routes = RouteTable::new(&config);
        let active = route(&config, 2, "node-b");
        routes.install(active.clone()).expect("install route");

        assert!(matches!(
            routes.install(route(&config, 1, "node-a")),
            Err(RouteError::Rollback)
        ));
        assert!(matches!(
            routes.install(route(&config, 2, "node-a")),
            Err(RouteError::Conflict)
        ));
        assert_eq!(routes.active(), Some(&active));
        assert!(routes.install(active).is_ok());
    }

    #[test]
    fn route_wire_refuses_unknown_fields_nodes_bad_numbers_and_wrong_cluster() {
        let config = config();
        let valid = route(&config, 1, "node-a").to_wire_json();
        for invalid in [
            valid.replace("\"generation\":\"1\"", "\"generation\":\"01\""),
            valid.replace(
                "\"primary_node_id\":\"node-a\"",
                "\"primary_node_id\":\"node-z\"",
            ),
            valid.replace(
                &format!("\"cluster_id\":\"{CLUSTER}\""),
                "\"cluster_id\":\"00000000-0000-4000-8000-000000000099\"",
            ),
            valid.replace("}", ",\"endpoint\":\"http://evil:9\"}"),
        ] {
            assert!(
                Route::from_wire_json(&config, &invalid).is_err(),
                "accepted {invalid}"
            );
        }

        let duplicate = valid.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        );
        assert!(Route::from_wire_json(&config, &duplicate).is_err());
    }
}
