use crate::corosync;
use crate::corosync::receive_message;
use crate::mls_group_handler::MlsSwarmLogic;
use crate::MlsGroupHandler;
use anyhow::{Context, Result, Error};
use once_cell::sync::OnceCell;
use rust_corosync::cpg::Handle;
use std::net::SocketAddr;
use openmls::prelude::LeafNodeIndex;
use tls_codec::Serialize;
use tokio::net::UdpSocket;
use tokio::{select, signal};
use std::result::Result::Ok;
use tokio::sync::mpsc;
use std::thread;


// TODO: Should be fetched from a configuration file
const NODE_IP : &str = "10.10.0.2";
const RX_CMD_ADDR : &str = "10.10.0.2:8000";


const RX_MULTICAST_ADDR :&str = "239.255.0.1"; // NB!: No port specifcation, use SOCKET const





// TODO: Should be fetched from a configuration file
                                               //const TX_MULTICAST_ADDR: &str = "239.255.0.1";

const RX_DS_ADDR: &str = "127.0.0.1:6000";
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
        
        let rx_cmd_socket = UdpSocket::bind(RX_CMD_ADDR)
            .await
            .context("Failed to bind Command RX socket")?;
        log::info!(
            "Listening for Application messages on {}",
            RX_APPLICATION_ADDR
        );  
      
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
                    match self.mls_group_handler.process_incoming_delivery_service_message(&data) {
                        Ok(Some((commit, welcome))) => {
                            corosync::send_message(&self.corosync_handle, commit.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");
                            corosync::send_message(&self.corosync_handle, welcome.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");
                          
                        }
                        Ok(None) => {}
                        Err(e) => {
                            log::error!("Error processing incoming message from DS: {}", e);
                        }
                }
            }

                // Commands and AppData coming in from CMD-socket, being sent to MLS_group_handler for processing, then being sent matched based on operation. 

                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_cmd_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::info!("CMD → MLS: {} bytes from {}", size, src);

                    let command = parse_command(&buf[..size]);
                    match command {
                        Ok(Command::Add{key_package_bytes})=>{
                            let(group_commit,welcome)=self.mls_group_handler.add_new_member_from_bytes(&key_package_bytes);
                            corosync::send_message(&self.corosync_handle, group_commit.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");
                            corosync::send_message(&self.corosync_handle, welcome.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");
                        }
                        Ok(Command::AddPending) => {
                            let out = self.mls_group_handler.add_pending_key_packages()?;
                            if !out.is_empty() {
                                for (group_commit, welcome) in out {
                                    corosync::send_message(&self.corosync_handle, group_commit.tls_serialize_detached().expect("Error serializng").as_slice())
                                        .expect("Failed to send message through Corosync");
                                    corosync::send_message(&self.corosync_handle, welcome.tls_serialize_detached().expect("Error serializng").as_slice())
                                        .expect("Failed to send message through Corosync");
                                }
                            }
                        }
                        Ok(Command::Remove{index}) => {
                            let (commit, _welcome_option) = self.mls_group_handler.remove_member(LeafNodeIndex::new(index));
                            corosync::send_message(&self.corosync_handle, commit.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");

                        },
                        Ok(Command::Update) => {
                            let (commit, _welcome_option) = self.mls_group_handler.update_self();
                            corosync::send_message(&self.corosync_handle, commit.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");

                        },
                        Ok(Command::RetrieveRatchetTree) => { todo!()},
                        Ok(Command::ApplicationMsg{data}) => {
                            let out = self.mls_group_handler.process_outgoing_application_message(&data)
                        .expect("Error handling outgoing application data.");
                        tx_network_socket.send_to(out.as_slice(), "239.255.0.1:5001").await?;
                        },
                        Ok(Command::BroadcastKeyPackage) => {
                            let key_package = self.mls_group_handler.get_key_package();
                            corosync::send_message(&self.corosync_handle, &key_package.tls_serialize_detached().expect("Error serializng").as_slice())
                              .expect("Failed to send message through Corosync");
                        }
                        Err(_) => todo!(),
                                            }
                }

                // Encrypted AppData coming in from radio network, being sent to MLS_group_handler for decryption, then forwarded to Application
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
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


