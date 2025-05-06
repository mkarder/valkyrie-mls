use anyhow::{Context, Result};
use std::env;
use std::path::PathBuf;

pub mod authentication;
mod config;
pub mod mls_group_handler;

#[cfg(target_os = "linux")]
mod corosync;
#[cfg(target_os = "linux")]
mod router;

use config::Config;
use mls_group_handler::MlsEngine;

#[cfg(target_os = "linux")]
use router::Router;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    #[cfg(target_os = "linux")]
    {
        log::info!("[MAIN] Starting MLS Valkyrie...");

        // Use $USER environment variable to build the config path
        let username = env::var("HOME").expect("USER environment variable not set");
        let config_path = PathBuf::from(format!("/{}/valkyrie-mls/config.toml", username));
        log::info!("Using config path: {}", config_path.display());

        // Load config
        let config = Config::from_file(config_path.to_str().unwrap())
            .expect("Failed to read config file");

        // Start MLS system
        let mls_engine = MlsEngine::new(config.mls.clone());
        let mut router = Router::new(mls_engine, config.router.clone());

        // Run main loop
        router.run_main_loop().await.context("Router loop failed")?;

        log::info!("[MAIN] Stopping MLS Valkyrie...");
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::warn!("[MAIN] ⚠️ Running in non-Linux environment. Exiting. ⚠️");
    }

    Ok(())
}
