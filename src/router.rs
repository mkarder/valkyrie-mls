use crate::mls_group_handler::MlsSwarmLogic;
use crate::{corosync, Corosync};
use crate::{mls_group_handler, MlsGroupHandler};
use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::{select, signal};

// TODO: Should be fetched from a configuration file
const RX_MULTICAST_ADDR: &str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const
const TX_MULTICAST_ADDR: &str = "239.255.0.1";

const RX_DS_ADDR: &str = "127.0.0.1:6000";
const TX_DS_ADDR: &str = "127.0.0.1:6001";

const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

const RX_MLS_ADDR: &str = "127.0.0.1:8000";
const TX_MLS_ADDR: &str = "127.0.0.1:8001";

pub struct Router {
    mls_group_handler: MlsGroupHandler,
    corosync: Corosync,
}

impl Router {
    pub fn new(mls_group_handler: MlsGroupHandler, corosync: Corosync) -> Self {
        Self {
            mls_group_handler,
            corosync,
        }
    }

    pub async fn run_main_loop(&mut self) -> Result<()> {
        let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR).await?;
        let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR).await?;

        let rx_network_socket = UdpSocket::bind("0.0.0.0:5000").await?; // Multicast RX
        rx_network_socket.join_multicast_v4(RX_MULTICAST_ADDR.parse()?, "0.0.0.0".parse()?)?;

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
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("DS → MLS: {} bytes from {}", size, src);
                    self.mls_group_handler.process_incoming_delivery_service_message(&buf[..size])
                        .expect("Error handling incoming message from DS");
                }


                // MLS → DS
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; 1024];
                    let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
                } => {
                    log::info!("MLS → DS: {} bytes from {}", size, src);
                    let data = self.mls_group_handler.process_outgoing_application_message(&buf[..size])
                        .expect("Error handling outgoing MLS config.");
                    //tx_ds_socket.send_to(&buf[..size], TX_DS_ADDR).await?;
                    self.corosync.send_message(&self.corosync.handle, &data);
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




///Hva er funksjonen under? Funksjonen kalles ingen steder som jeg ser? Fjernes?

/*
Router logic
- From App                  over UDP        -> To MlsComponent
- From Delivery Service     over UnixSocket -> To MlsComponent
- From Network              over UDP        -> To MlsComponent
*/

#[allow(dead_code)]
#[tokio::main]
pub async fn main_loop() -> Result<()> {
    // Initialize logger for debugging
    env_logger::init();

    // RX Sockets (Router receiving data from components)
    let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR).await?;
    let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR).await?;
    let rx_mls_socket = UdpSocket::bind(RX_MLS_ADDR).await?;

    let rx_network_socket = UdpSocket::bind("0.0.0.0:5000").await?; // Multicast RX
    rx_network_socket.join_multicast_v4(RX_MULTICAST_ADDR.parse()?, "0.0.0.0".parse()?)?;

    // TX Sockets (Router sending data to components)
    let tx_ds_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tx_app_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tx_mls_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let tx_network_socket = UdpSocket::bind("0.0.0.0:5001").await?; // Multicast TX
    tx_network_socket.set_multicast_loop_v4(true)?;

    loop {
        select! {
            biased;
            // DS → MLS
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_ds_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("DS → MLS: {} bytes from {}", size, src);
                tx_mls_socket.send_to(&buf[..size], TX_MLS_ADDR).await?;
            }

            // Application → MLS
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("Application → MLS: {} bytes from {}", size, src);
                tx_mls_socket.send_to(&buf[..size], TX_MLS_ADDR).await?;
            }

            // Network → MLS (Multicast RX)
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("Network → MLS: {} bytes from {}", size, src);
                tx_mls_socket.send_to(&buf[..size], TX_MLS_ADDR).await?;
            }

            // CLI -> MLS


            // MLS → Application
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_mls_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("MLS → Application: {} bytes from {}", size, src);
                tx_app_socket.send_to(&buf[..size], TX_APPLICATION_ADDR).await?;
            }

            // MLS → DS
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_mls_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("MLS → DS: {} bytes from {}", size, src);
                tx_ds_socket.send_to(&buf[..size], TX_DS_ADDR).await?;
            }

            // MLS → Network (Multicast TX)
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; 1024];
                let (size, src) = rx_mls_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; 1024])>
            } => {
                log::info!("MLS → Network: {} bytes from {}", size, src);
                tx_network_socket.send_to(&buf[..size], (TX_MULTICAST_ADDR, 5001)).await?;
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
