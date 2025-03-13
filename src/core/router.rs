use crate::core::message::Message;
use crate::mls::group::MlsHandler;
use crate::transport::socket::SocketHandler;

pub struct Router {
    mls_handler: MlsHandler,
    socket: SocketHandler,
}

impl Router {
    pub fn new() -> Self {
        Router {
            mls_handler: MlsHandler::new(),
            socket: SocketHandler::new(),
        }
    }

    pub fn route(&mut self, msg: Message) {
        match msg {
            Message::ApplicationData(data) => {
                self.socket.send(data);
            }
            Message::ProtocolMessage(mls_msg) => {
                self.mls_handler.handle_mls_message(mls_msg);
            }
        }
    }
}
