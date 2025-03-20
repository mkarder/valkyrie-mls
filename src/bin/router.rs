use std::net::SocketAddr;

use tokio::net::UdpSocket;
use tokio::{select, signal};
use anyhow::Result;


// TODO: Should be fetched from a configuration file
const RX_MULTICAST_ADDR :&str = "239.255.0.1"; // NB!: No port specifcation needed here
const TX_MULTICAST_ADDR: &str = "239.255.0.1";

const RX_DS_ADDR: &str = "127.0.0.1:6000";
const TX_DS_ADDR: &str = "127.0.0.1:6001"; 

const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

const RX_MLS_ADDR: &str = "127.0.0.1:8000";
const TX_MLS_ADDR: &str = "127.0.0.1:8001";


/*  
Router logic
- From App                  over UDP        -> To MlsComponent      over UnixSocket
- From Delivery Service     over UnixSocket -> To MlsComponent      over UnixSocket 
- From Network              over UDP        -> To MlsComponent      over UnixSocket

- From MlsComponent         over UnixSocket -> To App               over UDP
- From MlsComponent         over UnixSocket -> To Network           over UDP
- From MlsComponent         over UnixSocket -> To Delivery Service  over UnixSocket
*/
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger for debugging
    env_logger::init();

    // RX Sockets (Router receiving data from components)
    let rx_ds_socket = UdpSocket::bind(RX_DS_ADDR).await?;
    let rx_app_socket = UdpSocket::bind(RX_APPLICATION_ADDR).await?;
    let rx_mls_socket = UdpSocket::bind(RX_MLS_ADDR).await?;
    
    let rx_network_socket = UdpSocket::bind("0.0.0.0:5000").await?; // Multicast RX
    rx_network_socket.join_multicast_v4(
        RX_MULTICAST_ADDR.parse()?, 
        "0.0.0.0".parse()?
    )?;

    // TX Sockets (Router sending data to components)
    let tx_ds_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tx_app_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let tx_mls_socket = UdpSocket::bind("0.0.0.0:0").await?;

    let tx_network_socket = UdpSocket::bind("0.0.0.0:5001").await?; // Multicast TX
    tx_network_socket.set_multicast_loop_v4(true)?;


    loop {
        select! {
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


