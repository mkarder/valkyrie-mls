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

        // Try to get the user home directory in a fallible way
        let user_home = match env::var("SUDO_USER") {
            Ok(user) => PathBuf::from(format!("/home/{}", user)),
            Err(_) => home::home_dir().context("Could not determine user home directory")?,
        };

        // Build the full config path
        let config_path = user_home.join("valkyrie-mls").join("config.toml");
        log::info!("[MAIN] Using config path: {}", config_path.display());

        // Load config with context in case of error
        let config = Config::from_file(config_path.to_str().unwrap())
            .context("Failed to load config file")?;

        // Initialize core components
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
