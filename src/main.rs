mod mls_group_handler;
mod router;

use mls_group_handler::MlsGroupHandler;
use router::Router;
use anyhow::{Ok, Result};

#[tokio::main]
async fn main() -> Result<()>{
    env_logger::init();
    log::info!("Starting MLS Valkyrie...");

    let mls_group_handler = MlsGroupHandler::new();

    let mut router = Router::new(mls_group_handler);
    router.run_main_loop().await?;
    
    Ok(())
}