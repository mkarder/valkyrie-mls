mod mls_group_handler;
mod router;
mod corosync;
mod config;

use config::Config;
use mls_group_handler::MlsGroupHandler;
use router::Router;
use anyhow::{Ok, Result};

#[tokio::main]
async fn main() -> Result<()>{
    env_logger::init();
    log::info!("Starting MLS Valkyrie...");

    let config = Config::from_file("./config.toml").unwrap();

    let mls_group_handler = MlsGroupHandler::new(config.mls.clone());

    let mut router = Router::new(mls_group_handler, config.router.clone());
    router.run_main_loop().await?;
    
    log::info!("Stopping MLS Valkyrie...");

    Ok(())
}