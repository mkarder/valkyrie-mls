// src/config.rs
use anyhow::Result;
use serde::Deserialize;
use std::fs;

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
    pub fn from_file(path: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }
}
