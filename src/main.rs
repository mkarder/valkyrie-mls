pub mod authentication;
mod config;
pub mod mls_group_handler;
use anyhow::{Ok, Result};

#[cfg(target_os = "linux")]
mod corosync;
#[cfg(target_os = "linux")]
mod router;
use config::Config;
use mls_group_handler::MlsEngine;
#[cfg(target_os = "linux")]
use router::Router;
use std::env;


#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    #[cfg(target_os = "linux")]
    {
        log::info!("Starting MLS Valkyrie...");
        let config_path = format!("{}/valkyrie-mls/config.toml", env::var("HOME").unwrap());
        let config = Config::from_file(config_path.as_str()).unwrap();

        let mls_engine = MlsEngine::new(config.mls.clone());

        let mut router = Router::new(mls_engine, config.router.clone());
        router.run_main_loop().await?;

        log::info!("Stopping MLS Valkyrie...");
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::info!("⚠️Running in non-linux environment. Exiting. ⚠️");
    }

    Ok(())
}
