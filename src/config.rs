// src/config.rs
use ::config::{Config as RawConfig, Environment, File};
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub router: RouterConfig,
    pub mls: MlsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RouterConfig {
    pub rx_cmd_sock_addr: String,
    pub rx_app_sock_addr: String,
    pub tx_app_sock_addr: String,
    pub multicast_ip: String,
    pub multicast_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MlsConfig {
    pub gcs_id: u32,
    pub node_id: u32,
    pub credential_type: String,
    pub update_interval_secs: u64,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut builder = RawConfig::builder()
            .add_source(File::from(Path::new(path)))
            .add_source(Environment::default());

        // Manually map flat env vars to nested fields
        if let Ok(val) = std::env::var("NODE_ID") {
            builder = builder.set_override("mls.node_id", val)?;
        }
        if let Ok(val) = std::env::var("GCS_ID") {
            builder = builder.set_override("mls.gcs_id", val)?;
        }
        if let Ok(val) = std::env::var("CREDENTIAL_TYPE") {
            builder = builder.set_override("mls.credential_type", val)?;
        }
        if let Ok(val) = std::env::var("UPDATE_INTERVAL_SECS") {
            builder = builder.set_override("mls.update_interval_secs", val)?;
        }

        // Add other mappings as needed...
        // For router section:
        if let Ok(val) = std::env::var("RX_CMD_SOCK_ADDR") {
            builder = builder.set_override("router.rx_cmd_sock_addr", val)?;
        }

        let config = builder.build()?;
        let typed: Config = config.try_deserialize()?;
        Ok(typed)
    }
}
