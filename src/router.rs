use crate::corosync;
use crate::corosync::receive_message;
use crate::mls_group_handler::MlsSwarmLogic;
use crate::MlsGroupHandler;
use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use rust_corosync::cpg::Handle;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::{select, signal, task};
use std::thread;


// TODO: Should be fetched from a configuration file
const RX_MULTICAST_ADDR: &str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const
                                               //const TX_MULTICAST_ADDR: &str = "239.255.0.1";
const RX_DS_ADDR: &str = "127.0.0.1:6000";
const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

//Global transmission channel for Corosync
pub static TX_CHANNEL: OnceCell<mpsc::Sender<Vec<u8>>> = OnceCell::new();

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
        // Bind UDP sockets
        let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR)
            .await
            .context("Failed to bind DS RX socket")?;
        log::info!("Listening for Delivery Service messages on {}", RX_DS_ADDR);

        let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR)
            .await
            .context("Failed to bind Application RX socket")?;
        log::info!(
            "Listening for Application messages on {}",
            RX_APPLICATION_ADDR
        );

        let rx_network_socket = UdpSocket::bind("0.0.0.0:5000")
            .await
            .context("Failed to bind Multicast RX socket")?;
        rx_network_socket
            .join_multicast_v4(RX_MULTICAST_ADDR.parse()?, "0.0.0.0".parse()?)
            .context("Failed to join multicast group")?;
        log::info!("Joined multicast group {} on port 5000", RX_MULTICAST_ADDR);

        let tx_app_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind Application TX socket")?;

        let tx_network_socket = UdpSocket::bind("0.0.0.0:5001")
            .await
            .context("Failed to bind Multicast TX socket")?;
        tx_network_socket.set_multicast_loop_v4(true)?;

        let (tx_corosync_channel, mut rx_corosync_channel) = mpsc::channel::<Vec<u8>>(32);
        init_global_channel(tx_corosync_channel);

        /*
               // Spawn a blocking task to handle incoming Corosync messages
               let handle_clone = self.corosync_handle.clone();
               task::spawn_blocking(move || { //spawn_blocking
                   receive_message(&handle_clone).expect("Error receiving message from Corosync");
                   log::info!("Got milk");

               });
        */


        let handle_clone = self.corosync_handle.clone();
        thread::spawn(move || {
            if let Err(e) = receive_message(&handle_clone) {
                eprintln!("Error receiving message from Corosync: {:?}", e);
            } else {
                log::info!("Got milk");
            }
            log::info!("Got works");

        });

        loop {
            select! {
                biased;
                //  MLS commit messages coming from Corosync being sent to MLS_group_handler for processing
                Some(data) = rx_corosync_channel.recv() => {
                    log::info!("Corosync → MLS: {} bytes received", data.len());
                    self.mls_group_handler
                        .process_incoming_delivery_service_message(&data)
                        .context("Failed to process message from Corosync")?;
                }

                // MLS commit messages coming from MLS_group_handler being sent to Corosync for ordered delivery
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("MLS → DS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler
                        .process_outgoing_application_message(&buf[..size])
                        .context("Failed to process outgoing DS message")?;
                    corosync::send_message(&self.corosync_handle, &data)
                        .expect("Failed to send message through Corosync");
             }

                // AppData coming in from Application, being sent to MLS_group_handler for encryption, then being sent to the Radio Network
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("Application → MLS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler
                        .process_outgoing_application_message(&buf[..size])
                        .context("Failed to process outgoing app message")?;
                    tx_network_socket
                        .send_to(data.as_slice(), "239.255.0.1:5001")
                        .await
                        .context("Failed to send AppData as multicast packet to radio network")?;
                }

                // Encrypted AppData coming in from radio network, being sent to MLS_group_handler for decryption, then forwarded to Application
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("Network → MLS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler
                        .process_incoming_network_message(&buf[..size])
                        .expect("Failed to process incoming multicast packet.");
                    tx_app_socket
                        .send_to(data.as_slice(), TX_APPLICATION_ADDR)
                        .await
                        .context("Failed to forward packet to application")?;
                }

                // Handle Ctrl+C (Shutdown)
                _ = signal::ctrl_c() => {
                    println!("\n🛑 Ctrl+C detected! Shutting down gracefully...");
                    // Finalize Corosync to unblock the blocking receive thread
                    log::info!(" Ctrl+C detected! Shutting down gracefully...");
                    rust_corosync::cpg::finalize(self.corosync_handle).expect("Failed to finalize Corosync");
                    log::info!(" Finalized called");

                    break;
                }

            }
        }
        log::info!("Router main loop exited.");
        Ok(())
    }
}
