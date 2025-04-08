pub mod mls_group_handler;
mod config;
use anyhow::{Ok, Result};

#[cfg(target_os = "linux")] 
mod router;
#[cfg(target_os = "linux")]
mod corosync;
use config::Config;
use mls_group_handler::MlsEngine;
#[cfg(target_os = "linux")]
use router::Router;


#[tokio::main]
async fn main() -> Result<()>{
    env_logger::init();
    
    #[cfg(target_os = "linux")] {
        log::info!("Starting MLS Valkyrie...");
        let config = Config::from_file("./config.toml").unwrap();

        let mls_engine = MlsEngine::new(config.mls.clone());

        let mut router = Router::new(mls_engine, config.router.clone());
        router.run_main_loop().await?;
        
        log::info!("Stopping MLS Valkyrie...");       
    }

    #[cfg(not(target_os = "linux"))] {
        log::info!("⚠️Running in non-linux environment. Exiting. ⚠️");
    }

    Ok(())
}