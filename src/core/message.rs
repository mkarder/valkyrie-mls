pub enum Message {
    ApplicationData(Vec<u8>),
    ProtocolMessage(Vec<u8>),
}
