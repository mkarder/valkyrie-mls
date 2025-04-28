use crate::mls_group_handler::{
    MlsAutomaticRemoval, MlsGroupDiscovery, MlsSwarmLogic, MlsSwarmState,
};

use crate::config::RouterConfig;
use crate::corosync::receive_message;
use crate::{corosync, mls_group_handler::MlsEngine};
use anyhow::{Context, Error, Result};
use once_cell::sync::OnceCell;
use openmls::prelude::LeafNodeIndex;
use rust_corosync::cpg::Handle;
use rust_corosync::NodeId;
use std::env;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::result::Result::Ok;
use std::thread;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Duration;

use tokio::{select, signal};

const MLS_MSG_BUFFER_SIZE: usize = 16384; // 16KB

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
    AddPending,
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

    match MlsOperation::try_from(op_code)
        .map_err(|_| "Invalid opcode")
        .unwrap()
    {
        MlsOperation::Add => Ok(Command::Add {
            key_package_bytes: payload.to_vec(),
        }),
        MlsOperation::AddPending => Ok(Command::AddPending),
        MlsOperation::Remove => {
            if payload.len() < 4 {
                return Err(Error::msg(
                    "Invalid Remove payload. Should be u32 (4 bytes long)",
                ));
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

//Global transmission channel for Corosync
pub static MLS_HANDSHAKE_CHANNEL: OnceCell<mpsc::Sender<Vec<u8>>> = OnceCell::new();

pub fn init_global_channel(tx: mpsc::Sender<Vec<u8>>) {
    MLS_HANDSHAKE_CHANNEL
        .set(tx)
        .expect("Global MLS_HANDSHAKE_CHANNEL already initialized");
}

pub static SIG_CHANNEL: OnceCell<mpsc::Sender<CorosyncSignal>> = OnceCell::new();

pub fn init_signal_channel(tx: mpsc::Sender<CorosyncSignal>) {
    SIG_CHANNEL
        .set(tx)
        .expect("Global SIG_CHANNEL already initialized");
}

#[derive(Debug, Clone)]
pub enum CorosyncSignal {
    NodeJoined(Vec<NodeId>),
    NodeLeft(Vec<NodeId>),
    GroupStatus(Vec<NodeId>),
}

pub struct Router {
    mls_group_handler: MlsEngine,
    corosync_handle: Handle,
    config: RouterConfig,
}

impl Router {
    pub fn new(mls_group_handler: MlsEngine, config: RouterConfig) -> Self {
        let handle = corosync::initialize();
        Self {
            mls_group_handler,
            corosync_handle: handle,
            config,
        }
    }

    pub async fn run_main_loop(&mut self) -> Result<()> {
        // Bind UDP sockets
        let rx_cmd_socket = UdpSocket::bind(self.config.rx_cmd_sock_addr.clone())
            .await
            .context("Failed to bind Command RX socket")?;
        log::debug!(
            "[ROUTER] Listening for Command messages on {}",
            self.config.rx_cmd_sock_addr
        );

        //Application UDP Sockets (Send and receive from application)
        let rx_app_socket = UdpSocket::bind(self.config.rx_app_sock_addr.clone())
            .await
            .context("Failed to bind Application RX socket")?;

        log::debug!(
            "[ROUTER] Listening for AppData coming from Application on {}",
            self.config.rx_app_sock_addr
        );

        let tx_app_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind Application TX socket")?;

        //Radio Network Multicast Sockets (Send and receive from radio network)
        // Get interface IP from env
        let node_ip_str = env::var("NODE_IP").context("NODE_IP not set")?;
        let node_ip: Ipv4Addr = node_ip_str.parse().context("Invalid NODE_IP format")?;

        let rx_network_socket = UdpSocket::bind(format!(
            "{}:{}",
            self.config.multicast_ip, self.config.multicast_port
        ))
        .await
        .context("Failed to bind Multicast RX socket")?;
        rx_network_socket
            .join_multicast_v4(self.config.multicast_ip.parse()?, node_ip) //Try with your own ip address as interface, 10.10.0.x
            .context("Failed to join multicast group")?;

        log::debug!(
            "[ROUTER] Joined multicast group {} on port {} with local iface ip {}",
            self.config.multicast_ip,
            self.config.multicast_port,
            node_ip
        );

        let tx_network_socket =
            UdpSocket::bind(format!("{}:{}", node_ip, self.config.multicast_port)) //Try with own ip address
                .await
                .context("Failed to bind Multicast TX socket")?;
        tx_network_socket.set_multicast_loop_v4(false)?;
        log::debug!(
            "[ROUTER] Bound multicast TX socket to {}:{}. Multicast loopback is disabled.",
            node_ip,
            self.config.multicast_port
        );
        log::info!("[ROUTER] Socket Creation Completed.");

        let (tx_corosync_channel, mut rx_corosync_channel) = mpsc::channel::<Vec<u8>>(32);
        init_global_channel(tx_corosync_channel);

        let (tx_corosync_signal, mut rx_corosync_signal) = mpsc::channel::<CorosyncSignal>(16);
        init_signal_channel(tx_corosync_signal);

        let handle_clone = self.corosync_handle.clone();
        thread::spawn(move || {
            if let Err(e) = receive_message(&handle_clone) {
                log::error!("Error receiving message from Corosync: {:?}", e);
            }
        });

        // Thread for generating regular update messages
        let mut update_interval = tokio::time::interval(Duration::from_secs(
            self.mls_group_handler.update_interval_secs(),
        ));

        loop {
            select! {
                biased;
                //  MLS commit messages coming from Corosync being sent to MLS_group_handler for processing
                Some(data) = rx_corosync_channel.recv() => {
                    log::debug!("[ROUTER] Corosync → MLS: Received {} bytes from Corosync", data.len());
                    match self.mls_group_handler.process_incoming_delivery_service_message(&data) {
                        Ok(Some((commit, welcome))) => {
                            log::info!("[ROUTER] Processing incoming delivery service message: Commit and Welcome generated.");
                            corosync::send_message(&self.corosync_handle, commit.as_slice())
                                .expect("[ROUTER] Failed to send Commit message through Corosync");
                            log::debug!("[ROUTER] Commit message sent to Corosync.");
                            corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                .expect("[ROUTER] Failed to send Welcome message through Corosync");
                            log::debug!("[ROUTER] Welcome message sent to Corosync.");
                        }
                        Ok(None) => {
                            log::debug!("[ROUTER] No Commit or Welcome generated from incoming delivery service message.");
                        }
                        Err(e) => {
                            log::error!("[ROUTER] Error processing incoming delivery service message: {}", e);
                        }
                    }
                }

                // (Totem) Corosync Membership changes
                Some(signal) = rx_corosync_signal.recv() => {
                    match signal {
                        CorosyncSignal::NodeJoined(node_ids)=>{log::debug!("[ROUTER] Notified: Nodes joined: {:?}",node_ids);}
                        CorosyncSignal::NodeLeft(node_ids)=>{
                            log::info!("[ROUTER] Notified: Nodes left: {:?}",node_ids);
                            if!node_ids.is_empty(){self.mls_group_handler.schedule_removal(node_ids.into_iter().map(Into::into).collect());}}
                        CorosyncSignal::GroupStatus(group) => self.mls_group_handler.update_totem_group(group.into_iter().map(Into::into).collect()),
                                            }
                }

                // Commands coming from CMD-socket.
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_cmd_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::debug!("[ROUTER] CMD → MLS: Received {} bytes from {}", size, src);

                    let command = parse_command(&buf[..size]);
                    match command {
                        Ok(Command::Add { key_package_bytes }) => {
                            log::info!(
                                "[ROUTER] Received Add command for key_package ({} bytes).",
                                key_package_bytes.len()
                            );
                            let (group_commit, welcome) =
                                self.mls_group_handler.add_new_member_from_bytes(&key_package_bytes);
                            log::debug!("[ROUTER] Add command processed: Commit and Welcome generated.");
                            corosync::send_message(&self.corosync_handle, group_commit.as_slice())
                                .expect("Failed to send Commit message through Corosync");
                            log::debug!("[ROUTER] Commit message sent to Corosync.");
                            corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                .expect("Failed to send Welcome message through Corosync");
                            log::debug!("[ROUTER] Welcome message sent to Corosync.");
                        }
                        Ok(Command::AddPending) => {
                            log::info!("[ROUTER] Received AddPending command.");
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((group_commit, welcome))) => {
                                    log::info!("[ROUTER] AddPending command processed: Commit and Welcome generated.");
                                    corosync::send_message(&self.corosync_handle, group_commit.as_slice())
                                        .expect("Failed to send Commit message through Corosync");
                                    log::debug!("[ROUTER] Commit message sent to Corosync.");
                                    corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                        .expect("Failed to send Welcome message through Corosync");
                                    log::debug!("[ROUTER] Welcome message sent to Corosync.");
                                }
                                Ok(None) => {log::debug!("[ROUTER] Call for add_pending_key_packages but No key packages to add");}
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing AddPending command: {}", e);
                                }
                            }
                        }
                        Ok(Command::Remove { index }) => {
                            log::info!("[ROUTER] Received Remove command for LeafNode at index {}.", index);
                            let (commit, _welcome_option) =
                                self.mls_group_handler.remove_member(LeafNodeIndex::new(index));
                            log::debug!("Remove command processed: Commit generated.");
                            corosync::send_message(&self.corosync_handle, commit.as_slice())
                                .expect("Failed to send Commit message through Corosync");
                            log::debug!("Commit message sent to Corosync.");
                        }
                        Ok(Command::Update) => {
                            log::info!("[ROUTER] Received Update command.");
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_option)) => {
                                    log::debug!("[ROUTER] Update command processed: Commit generated.");
                                    corosync::send_message(&self.corosync_handle, commit.as_slice())
                                        .expect("Failed to send Commit message through Corosync");
                                    log::debug!("[ROUTER] Commit message sent to Corosync.");
                                    if let Some(welcome) = welcome_option {
                                        log::debug!("Update command processed: Welcome generated.");
                                        corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                            .expect("Failed to send Welcome message through Corosync");
                                        log::debug!("[ROUTER] Welcome message sent to Corosync.");
                                    }
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing Update command: {}", e);
                                }
                            }

                        }
                        Ok(Command::RetrieveRatchetTree) => {
                            log::info!("[ROUTER] Received RetrieveRatchetTree command. \n Not implemented yet. Skipping operation...");
                        }
                        Ok(Command::ApplicationMsg { data }) => {
                            log::info!(
                                "[ROUTER] Received ApplicationMsg command for {} bytes.",
                                data.len()
                            );
                            match self
                                .mls_group_handler
                                .process_outgoing_application_message(&data)
                            {
                                Ok(out) => {
                                    log::debug!(
                                        "[ROUTER] Application message processed: Sending {} bytes to {}:{}.",
                                        out.len(),
                                        self.config.multicast_ip,
                                        self.config.multicast_port
                                    );
                                    tx_network_socket
                                        .send_to(
                                            out.as_slice(),
                                            format!("{}:{}", self.config.multicast_ip, self.config.multicast_port),
                                        )
                                        .await
                                        .context("Failed to forward packet to network")?;
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing ApplicationMsg command: {}", e);
                                }
                            }
                        }

                        Ok(Command::BroadcastKeyPackage) => {
                            log::debug!("[ROUTER] Received BroadcastKeyPackage command.");
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {

                                    log::info!("[ROUTER] BroadcastKeyPackage command processed: Sending key package.");

                                    corosync::send_message(&self.corosync_handle, key_package.as_slice())
                                        .expect("Failed to send key package through Corosync");
                                    log::debug!("Key package sent to Corosync.");
                                }
                                Err(e) => {

                                    log::error!("Error processing BroadcastKeyPackage command: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Error parsing command: {}", e);
                        }
                    }
                }
              // Encrypted AppData coming in from radio network, being sent to MLS_group_handler for decryption,
              //then forwarded to Application
              Ok((size, src, buf)) = async {
                let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
            } => {
                log::debug!("Network → MLS: {} bytes from {}", size, src);
                match self.mls_group_handler.process_incoming_network_message(&buf[..size]){
                    Ok(data) => {
                        tx_app_socket
                            .send_to(data.as_slice(), self.config.tx_app_sock_addr.clone())
                            .await
                            .context("Failed to forward packet to application")?;
                    }
                    Err(e) => {
                        log::error!("Error processing incoming network message: {}", e);
                        // Optionally: continue, return, or handle differently
                    }
                }
            }

            // Unencrypted AppData coming in from application, being sent to MLS_group_handler for encryption, then forwarded to radio network.
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
            } => {
                log::debug!("Application → MLS: {} bytes from {}", size, src);
                match self.mls_group_handler.process_outgoing_application_message(&buf[..size]){
                    Ok(data) => {
                        tx_network_socket
                            .send_to(data.as_slice(), format!("{}:{}", self.config.multicast_ip, self.config.multicast_port))
                            .await
                            .context("Failed to forward packet to network")?;
                    }
                    Err(e) => {
                        log::error!("Error processing appData coming from application: {}", e);
                    }
                }
            }

                _ = update_interval.tick() => {
                    log::debug!("⏰ Scheduled Update Cycle scheduled self-update...");
                    match self.mls_group_handler.get_mls_group_state() {
                        MlsSwarmState::Alone => {
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {
                                    log::debug!("[ROUTER] Alone in MlsGroup. Broadcasting key package.");
                                    corosync::send_message(&self.corosync_handle, key_package.as_slice())
                                        .expect("Failed to send key package through Corosync");
                                    log::debug!("[ROUTER] Key package sent to Corosync.");
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error Broadcasting KeyPackage: {}", e);
                                }
                            }
                        },
                        MlsSwarmState::SubGroup => {
                            // Check for pending Removals
                            if self.mls_group_handler.have_pending_removals() {
                                match self.mls_group_handler.remove_pending() {
                                    Ok((commit, welcome_option)) => {
                                        log::info!("✅ Automatic removal successful.");
                                        corosync::send_message(&self.corosync_handle, commit.as_slice())
                                        .expect("Failed to send message through Corosync");
                                        if let Some(welcome) = welcome_option {
                                            corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                            .expect("Failed to send message through Corosync");
                                        }
                                    }
                                    Err(e) => log::error!("❌ Automatic removal failed: {:?}", e),
                                }
                            }
                            // Check for pending Adds
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((group_commit, welcome))) => {
                                    log::info!("[ROUTER] Added pending key packages, sending commit and welcome.");
                                    corosync::send_message(&self.corosync_handle, group_commit.as_slice())
                                        .expect("Failed to send Commit message through Corosync");
                                    log::debug!("[ROUTER] Commit message sent to Corosync.");
                                    corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                        .expect("Failed to send Welcome message through Corosync");
                                    log::debug!("[ROUTER] Welcome message sent to Corosync.");
                                }
                                Ok(None) => {log::debug!("[ROUTER] No key packages to add");}
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing AddPending command: {}", e);
                                }
                            }

                            // Update self
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_option)) => {
                                    log::info!("✅ Automatic self-update successful.");
                                    corosync::send_message(&self.corosync_handle, commit.as_slice())
                                    .expect("Failed to send message through Corosync");
                                    if let Some(welcome) = welcome_option {
                                        corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                        .expect("Failed to send message through Corosync");
                                    }
                                }
                                Err(e) => log::error!("❌ Self-update failed: {:?}", e),
                            }

                            // Broadcast KeyPackage
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {
                                    log::debug!("[ROUTER] GCS not in MlsGroup. Broadcasting key package.");
                                    corosync::send_message(&self.corosync_handle, key_package.as_slice())
                                        .expect("Failed to send key package through Corosync");
                                    log::debug!("[ROUTER] Key package sent to Corosync.");
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error Broadcasting KeyPackage: {}", e);
                                }
                            }
                        },
                        MlsSwarmState::MainGroup => {
                            // Check for pending Removals
                            if self.mls_group_handler.have_pending_removals() {
                                match self.mls_group_handler.remove_pending() {
                                    Ok((commit, welcome_option)) => {
                                        log::info!("✅ Automatic removal successful.");
                                        corosync::send_message(&self.corosync_handle, commit.as_slice())
                                        .expect("Failed to send message through Corosync");
                                        if let Some(welcome) = welcome_option {
                                            corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                            .expect("Failed to send message through Corosync");
                                        }
                                    }
                                    Err(e) => log::error!("❌ Automatic removal failed: {:?}", e),
                                }
                            }
                            // Check for pending Adds
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((group_commit, welcome))) => {
                                    log::info!("[ROUTER] Added pending key packages, sending commit and welcome.");
                                    corosync::send_message(&self.corosync_handle, group_commit.as_slice())
                                        .expect("Failed to send Commit message through Corosync");
                                    log::debug!("[ROUTER] Commit message sent to Corosync.");
                                    corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                        .expect("Failed to send Welcome message through Corosync");
                                    log::debug!("[ROUTER] Welcome message sent to Corosync.");
                                }
                                Ok(None) => {log::debug!("[ROUTER] No key packages to add");}
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing AddPending command: {}", e);
                                }
                            }

                            // Update self
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_option)) => {
                                    log::info!("✅ Automatic self-update successful.");
                                    corosync::send_message(&self.corosync_handle, commit.as_slice())
                                    .expect("Failed to send message through Corosync");
                                    if let Some(welcome) = welcome_option {
                                        corosync::send_message(&self.corosync_handle, welcome.as_slice())
                                        .expect("Failed to send message through Corosync");
                                    }
                                }
                                Err(e) => log::error!("❌ Self-update failed: {:?}", e),
                            }
                        }
                    }
                }

                // Handle Ctrl+C (Shutdown)
                _ = signal::ctrl_c() => {
                    println!("\n🛑 Ctrl+C detected! Shutting down gracefully...");
                    // Finalize Corosync to unblock the blocking receive thread
                    rust_corosync::cpg::finalize(self.corosync_handle).expect("Failed to finalize Corosync");
                    log::info!("Finalized called");
                    break;
                }

            }
        }
        log::info!("Router main loop exited.");
        Ok(())
    }
}
