pub struct MlsHandler;

impl MlsHandler {
    pub fn new() -> Self {
        MlsHandler
    }

    pub fn handle_mls_message(&self, msg: Vec<u8>) {
        println!("Handling MLS message...");
        // Call OpenMLS functions here
    }
}
