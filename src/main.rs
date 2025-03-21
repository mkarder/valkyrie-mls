mod mls_group_handler;

use mls_group_handler::MlsGroupHandler;

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    MlsGroupHandler::new();
    
}