use crate::mls_group_handler::MlsSwarmLogic;
use crate::MlsGroupHandler;
use std::net::SocketAddr;
use tls_codec::Serialize;
use tokio::net::UdpSocket;
use tokio::{select, signal};
use anyhow::Result;



// TODO: Should be fetched from a configuration file
const RX_MULTICAST_ADDR :&str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const

const RX_DS_ADDR: &str = "127.0.0.1:6000";
const TX_DS_ADDR: &str = "127.0.0.1:6001"; 

const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

const MLS_MSG_BUFFER_SIZE: usize = 2048; // TODO: Explain choice of this size  

/* 
enum MlsOperation {
    ADD : 0x00.
    REMOVE : 0x01,
    UPDATE : 0x02,
    APPLICATIOn_MSG : 0x03,
}
*/

pub struct Router {
    mls_group_handler: MlsGroupHandler,
}

impl Router {
    pub fn new(mls_group_handler: MlsGroupHandler) -> Self {
        Self { mls_group_handler }
    }

    pub async fn run_main_loop(&mut self) -> Result<()> {
        let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR).await?;
        let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR).await?;
        
        let rx_network_socket = UdpSocket::bind("0.0.0.0:5000").await?; // Multicast RX
        rx_network_socket.join_multicast_v4(
            RX_MULTICAST_ADDR.parse()?, 
            "0.0.0.0".parse()?
        )?;

        // TX Sockets (Router sending data to components)
        let tx_ds_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let tx_app_socket = UdpSocket::bind("0.0.0.0:0").await?;

        let tx_network_socket = UdpSocket::bind("0.0.0.0:5001").await?; // Multicast TX
        tx_network_socket.set_multicast_loop_v4(true)?;


        loop {
            select! {
                biased;
                // DS → MLS
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::info!("DS → MLS: {} bytes from {}", size, src);
                    match self.mls_group_handler.process_incoming_delivery_service_message(&buf[..size]) {
                        Ok(Some((commit, welcome))) => {
                            tx_ds_socket.send_to(commit.tls_serialize_detached().expect("Error serializng").as_slice(), TX_DS_ADDR).await?;
                            tx_ds_socket.send_to(welcome.tls_serialize_detached().expect("Error serializng").as_slice(), TX_DS_ADDR).await?;
                        },
                        Ok(None) => {}
                        Err(e) => {
                            log::error!("Error processing incoming message from DS: {}", e);
                        }
                    }
                }

                // Application → MLS
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::info!("Application → MLS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler.process_outgoing_application_message(&buf[..size])
                        .expect("Error handling outgoing application data.");
                    tx_network_socket.send_to(data.as_slice(), "239.255.0.1:5001").await?;
                }

                // Network → MLS (Multicast RX)
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::info!("Network → MLS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler.process_incoming_network_message(&buf[..size])
                        .expect("Error handling incoming network packet.");
                    tx_app_socket.send_to(data.as_slice(), TX_APPLICATION_ADDR).await?;
                }

                // Handle Ctrl+C (Shutdown)
                _ = signal::ctrl_c() => {
                    println!("\n🛑 Ctrl+C detected! Shutting down gracefully...");
                    println!("Server shut down.");
                    break;
                }
            }
        }
        Ok(())
        }
}





