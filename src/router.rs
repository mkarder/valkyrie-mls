use crate::corosync;
use crate::corosync::receive_message;
use crate::mls_group_handler::MlsSwarmLogic;
use crate::MlsGroupHandler;
use anyhow::Result;
use once_cell::sync::OnceCell;
use rust_corosync::cpg::Handle;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::{select, signal, task};

// TODO: Should be fetched from a configuration file
const RX_MULTICAST_ADDR: &str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const
                                               //const TX_MULTICAST_ADDR: &str = "239.255.0.1";

const RX_DS_ADDR: &str = "127.0.0.1:6000";

const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

pub static TX_CHANNEL: OnceCell<mpsc::Sender<Vec<u8>>> = OnceCell::new();

// Function to initialize the global sender exactly once:
pub fn init_global_channel(tx: mpsc::Sender<Vec<u8>>) {
    TX_CHANNEL
        .set(tx)
        .expect("Global TX_CHANNEL already initialized");
}

pub struct Router {
    mls_group_handler: MlsGroupHandler,
    corosync_handle: Handle,
}

impl Router {
    pub fn new(mls_group_handler: MlsGroupHandler) -> Self {
        let handle = corosync::initialize();

        Self {
            mls_group_handler,
            corosync_handle: handle,
        }
    }

    pub async fn run_main_loop(&mut self) -> Result<()> {
        let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR).await?;
        let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR).await?;

        let rx_network_socket = UdpSocket::bind("0.0.0.0:5000").await?; // Multicast RX
        rx_network_socket.join_multicast_v4(RX_MULTICAST_ADDR.parse()?, "0.0.0.0".parse()?)?;

        let tx_app_socket = UdpSocket::bind("0.0.0.0:0").await?;

        let tx_network_socket = UdpSocket::bind("0.0.0.0:5001").await?; // Multicast TX
        tx_network_socket.set_multicast_loop_v4(true)?;

        let (tx_corosync_channel, mut rx_corosync_channel) = mpsc::channel::<Vec<u8>>(32);
        init_global_channel(tx_corosync_channel);

        // Spawn a blocking task to handle incoming Corosync messages
        let handle_clone = self.corosync_handle.clone();
        task::spawn_blocking(move || {
            receive_message(&handle_clone).expect("Error receiving message from Corosync");
        });

        loop {
            select! {
                biased;
                // Corosync → MLS
                Some(data) = rx_corosync_channel.recv() => {
                    log::info!("Corosync → MLS: {} bytes received", data.len());
                    self.mls_group_handler
                        .process_incoming_delivery_service_message(&data)
                        .expect("Error handling incoming message from Corosync");
                }


                // MLS → Corosync
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("MLS → DS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler.process_outgoing_application_message(&buf[..size])
                        .expect("Error handling outgoing MLS config.");
                    //tx_ds_socket.send_to(&buf[..size], TX_DS_ADDR).await?;
                    //self.corosync.send_message(&self.corosync.handle, &data);
                    corosync::send_message(&self.corosync_handle, &data)
                        .expect("Error handling sending message through Corosync.");
                }


                // Application → MLS
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("Application → MLS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler.process_outgoing_application_message(&buf[..size])
                        .expect("Error handling outgoing application data.");
                    tx_network_socket.send_to(data.as_slice(), "239.255.0.1:5001").await?;
                }

                // Network → MLS (Multicast RX)
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
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
