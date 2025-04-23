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
        //let config_path = format!("{}/valkyrie-mls/config.toml", env::var("HOME").unwrap());
        //let config = Config::from_file(config_path.as_str()).unwrap();

        // Determine correct home directory
        let user_home = match env::var("SUDO_USER") {
            Ok(user) => PathBuf::from(format!("/home/{}", user)),
            Err(_) => home::home_dir().expect("Cannot determine home directory"),
        };

        // Construct full config path
        let config_path = user_home.join("valkyrie-mls").join("config.toml");

        log::info!("Using config path: {}", config_path.display());

        // Read config
        let config = Config::from_file(config_path.to_str().unwrap()).unwrap();

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
