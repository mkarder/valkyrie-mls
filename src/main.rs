pub mod authentication;
mod config;
pub mod mls_group_handler;
use anyhow::Result;

#[cfg(target_os = "linux")]
mod corosync;
#[cfg(target_os = "linux")]
mod router;
use config::Config;
use mls_group_handler::MlsEngine;
#[cfg(target_os = "linux")]
use router::Router;
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    #[cfg(target_os = "linux")]
    {
        log::info!("[MAIN] Starting MLS Valkyrie...");

        // Use $USER environment variable to build the config path
        let username = env::var("USER").expect("USER environment variable not set");
        let config_path = PathBuf::from(format!("/{}/valkyrie-mls/config.toml", username));
        log::info!("Using config path: {}", config_path.display());

        // Load config
        let config = Config::from_file(config_path.to_str().unwrap())
            .expect("Failed to read config file");

        // Start MLS system
        let mls_engine = MlsEngine::new(config.mls.clone());
        let mut router = Router::new(mls_engine, config.router.clone());
        router.run_main_loop().await?;

        log::info!("[MAIN] Stopping MLS Valkyrie...");
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::info!("[MAIN] ⚠️Running in non-linux environment. Exiting. ⚠️");
    }

    Ok(())
}
