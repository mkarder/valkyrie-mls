use crate::mls_group_handler::MlsSwarmLogic;
use crate::MlsGroupHandler;
use std::net::SocketAddr;
use openmls::prelude::LeafNodeIndex;
use tls_codec::Serialize;
use tokio::net::UdpSocket;
use tokio::{select, signal};
use anyhow::{Error, Result};
use std::result::Result::Ok;


// TODO: Should be fetched from a configuration file
const NODE_IP : &str = "10.10.0.2";
const RX_CMD_ADDR : &str = "10.10.0.2:8000";


const RX_MULTICAST_ADDR :&str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const

const RX_DS_ADDR: &str = "127.0.0.1:6000";
const TX_DS_ADDR: &str = "127.0.0.1:6001"; 

const RX_APPLICATION_ADDR: &str = "127.0.0.1:7000";
const TX_APPLICATION_ADDR: &str = "127.0.0.1:7001";

const MLS_MSG_BUFFER_SIZE: usize = 2048; // TODO: Explain choice of this size  

 
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsOperation {
    Add = 0x00,
    AddPending = 0x01,
    Remove = 0x02,
    Update = 0x03,
    RetrieveRatchetTree = 0x04,
    ApplicationMsg = 0x05,
    BroadcastKeyPackage = 0x06,
}

impl TryFrom<u8> for MlsOperation {
    type Error = anyhow::Error;

    fn try_from(byte: u8) -> Result<Self, Error> {
        match byte {
            0x00 => Ok(MlsOperation::Add),
            0x01 => Ok(MlsOperation::AddPending),
            0x02 => Ok(MlsOperation::Remove),
            0x03 => Ok(MlsOperation::Update),
            0x04 => Ok(MlsOperation::RetrieveRatchetTree),
            0x05 => Ok(MlsOperation::ApplicationMsg),
            0x06 => Ok(MlsOperation::BroadcastKeyPackage),
            _ => Err(Error::msg("Invalid MlsOperation byte")),
        }
    }
}

#[derive(Debug)]
pub enum Command {
    Add { key_package_bytes: Vec<u8> },
    AddPending ,
    Remove { index: u32 },
    Update,
    RetrieveRatchetTree,
    ApplicationMsg { data: Vec<u8> },
    BroadcastKeyPackage,
}

pub fn parse_command(buffer: &[u8]) -> Result<Command, Error> {
    if buffer.is_empty() {
        return Err(Error::msg("Empty command. Nothing in received buffer."));
    }

    let op_code = buffer[0];
    let payload = &buffer[1..];

    match MlsOperation::try_from(op_code).map_err(|_| "Invalid opcode").unwrap() {
        MlsOperation::Add => Ok(Command::Add {
                        key_package_bytes: payload.to_vec(),
            }),
        MlsOperation::AddPending => Ok(Command::AddPending),
        MlsOperation::Remove => {
                if payload.len() < 4 {
                    return Err(Error::msg("Invalid Remove payload. Should be u32 (4 bytes long)"))
                }
                let index = u32::from_be_bytes(payload[..4].try_into().unwrap());
                Ok(Command::Remove { index })
            }
        MlsOperation::Update => Ok(Command::Update),
        MlsOperation::RetrieveRatchetTree => Ok(Command::RetrieveRatchetTree),
        MlsOperation::ApplicationMsg => Ok(Command::ApplicationMsg {
                data: payload.to_vec(),
            }),
        MlsOperation::BroadcastKeyPackage => Ok(Command::BroadcastKeyPackage),
        }
}

pub fn serialize_command(cmd: &Command) -> Vec<u8> {
    match cmd {
        Command::Add { key_package_bytes } => {
                        let mut buf = vec![MlsOperation::Add as u8];
                        buf.extend_from_slice(key_package_bytes);
                        buf
            }
        Command::Remove { index } => {
                let mut buf = vec![MlsOperation::Remove as u8];
                buf.extend(&index.to_be_bytes());
                buf
            }
        Command::RetrieveRatchetTree => vec![MlsOperation::RetrieveRatchetTree as u8],
        Command::Update => { vec![MlsOperation::Update as u8] },
        Command::AddPending => { vec![MlsOperation::AddPending as u8]},
        Command::ApplicationMsg { data } => {
                let mut buf = vec![MlsOperation::ApplicationMsg as u8];
                buf.extend_from_slice(data);
                buf
            }
        Command::BroadcastKeyPackage => vec![MlsOperation::BroadcastKeyPackage as u8],
    }
}



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
                    let command = parse_command(&buf[..size]);
                    match command {
                        Ok(Command::Add{key_package_bytes})=>{
                            let(group_commit,welcome)=self.mls_group_handler.add_new_member_from_bytes(&key_package_bytes);
                            tx_ds_socket.send_to(group_commit.tls_serialize_detached().expect("Error serializing Group Commit").as_slice(), TX_DS_ADDR).await?;
                            tx_ds_socket.send_to(welcome.tls_serialize_detached().expect("Error serializing Welcome").as_slice(), TX_DS_ADDR).await?;
                        }
                        Ok(Command::AddPending) => {
                            let out = self.mls_group_handler.add_pending_key_packages()?;
                            if !out.is_empty() {
                                for (group_commit, welcome) in out {
                                    tx_ds_socket.send_to(group_commit.tls_serialize_detached().expect("Error serializing Group Commit").as_slice(), TX_DS_ADDR).await?;
                                    tx_ds_socket.send_to(welcome.tls_serialize_detached().expect("Error serializing Welcome").as_slice(), TX_DS_ADDR).await?;
                                }
                            }
                        }
                        Ok(Command::Remove{index}) => {
                            let (commit, _welcome_option) = self.mls_group_handler.remove_member(LeafNodeIndex::new(index));
                            tx_ds_socket.send_to(commit.tls_serialize_detached().expect("Error serializing Group Commit").as_slice(), TX_DS_ADDR).await?;

                        },
                        Ok(Command::Update) => {
                            let (commit, _welcome_option) = self.mls_group_handler.update_self();
                            tx_ds_socket.send_to(commit.tls_serialize_detached().expect("Error serializing Group Commit").as_slice(), TX_DS_ADDR).await?;

                        },
                        Ok(Command::RetrieveRatchetTree) => { todo!()},
                        Ok(Command::ApplicationMsg{data}) => {
                            let out = self.mls_group_handler.process_outgoing_application_message(&data)
                        .expect("Error handling outgoing application data.");
                        tx_network_socket.send_to(out.as_slice(), "239.255.0.1:5001").await?;
                        },
                        Ok(Command::BroadcastKeyPackage) => {
                            let key_package = self.mls_group_handler.get_key_package();
                            tx_ds_socket.send_to(&key_package.tls_serialize_detached().expect("Error serializing KeyPackage"), TX_DS_ADDR).await?;
                        }
                        Err(_) => todo!(),
                                            }
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





