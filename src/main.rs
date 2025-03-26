mod mls_group_handler;
mod router;
mod corosync;

use mls_group_handler::MlsGroupHandler;
use router::Router;
use anyhow::{Ok, Result};
use corosync::Corosync;

#[tokio::main]
async fn main() -> Result<()>{
    env_logger::init();
    log::info!("Starting MLS Valkyrie...");

    let mls_group_handler = MlsGroupHandler::new();
    let corosync = Corosync::new();

    let mut router = Router::new(mls_group_handler, corosync);
    router.run_main_loop().await?;
    
    Ok(())
}