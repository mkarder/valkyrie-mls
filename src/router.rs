use crate::mls_group_handler::{
    MlsAutomaticRemoval, MlsEngineError, MlsGroupDiscovery, MlsGroupReset, MlsSwarmLogic,
    MlsSwarmState,
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
use std::time::Instant;
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
pub static SIG_CHANNEL: OnceCell<mpsc::Sender<CorosyncSignal>> = OnceCell::new();

#[derive(Debug, Clone)]
pub enum CorosyncSignal {
    NodeJoined(Vec<NodeId>),
    NodeLeft(Vec<NodeId>),
    GroupStatus(Vec<NodeId>),
}

// Wrapper for sending messages to Corosync. Function will only log errors, not panic to avoid crashing.
macro_rules! try_send {
    ($handle:expr, $label:expr, $msg:expr) => {
        if let Err(e) = corosync::send_message($handle, $msg) {
            log::error!("[ROUTER] Failed to send {}: {}", $label, e);
        } else {
            log::debug!("[ROUTER] {} sent.", $label);
        }
    };
}

pub struct Router {
    mls_group_handler: MlsEngine,
    corosync_handle: Handle,
    config: RouterConfig,
    wrong_epoch_timer: Option<Instant>,
    wrong_epoch_timeout: Duration,
}

impl Router {
    pub fn new(mls_group_handler: MlsEngine, config: RouterConfig) -> Self {
        let handle = corosync::initialize();
        Self {
            mls_group_handler,
            corosync_handle: handle,
            config,
            wrong_epoch_timer: None,
            wrong_epoch_timeout: Duration::from_secs(5),
        }
    }

    pub async fn run_main_loop(&mut self) -> Result<()> {
        // Bind UDP sockets — fail early if these don't work
        let rx_cmd_socket = UdpSocket::bind(&self.config.rx_cmd_sock_addr)
            .await
            .with_context(|| {
                format!(
                    "Failed to bind Command RX socket at {}",
                    self.config.rx_cmd_sock_addr
                )
            })?;

        log::debug!(
            "[ROUTER] Listening for Command messages on {}",
            self.config.rx_cmd_sock_addr
        );

        let rx_app_socket = UdpSocket::bind(&self.config.rx_app_sock_addr)
            .await
            .with_context(|| {
                format!(
                    "Failed to bind Application RX socket at {}",
                    self.config.rx_app_sock_addr
                )
            })?;

        log::debug!(
            "[ROUTER] Listening for AppData coming from Application on {}",
            self.config.rx_app_sock_addr
        );

        let tx_app_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind Application TX socket")?;

        // Set up multicast sockets
        let node_ip_str = env::var("NODE_IP").context("NODE_IP not set")?;
        let node_ip: Ipv4Addr = node_ip_str
            .parse()
            .context("Failed to parse NODE_IP as IPv4 address")?;

        let rx_network_socket = UdpSocket::bind(format!(
            "{}:{}",
            self.config.multicast_ip, self.config.multicast_port
        ))
        .await
        .with_context(|| {
            format!(
                "Failed to bind Multicast RX socket on {}:{}",
                self.config.multicast_ip, self.config.multicast_port
            )
        })?;

        rx_network_socket
            .join_multicast_v4(
                self.config
                    .multicast_ip
                    .parse()
                    .context("Failed to parse multicast IP")?,
                node_ip,
            )
            .context("Failed to join multicast group")?;

        log::debug!(
            "[ROUTER] Joined multicast group {} on port {} with local iface ip {}",
            self.config.multicast_ip,
            self.config.multicast_port,
            node_ip
        );

        let tx_network_socket =
            UdpSocket::bind(format!("{}:{}", node_ip, self.config.multicast_port))
                .await
                .with_context(|| {
                    format!(
                        "Failed to bind Multicast TX socket on {}:{}",
                        node_ip, self.config.multicast_port
                    )
                })?;

        tx_network_socket
            .set_multicast_loop_v4(false)
            .context("Failed to disable multicast loopback")?;

        log::debug!(
            "[ROUTER] Bound multicast TX socket to {}:{}. Multicast loopback is disabled.",
            node_ip,
            self.config.multicast_port
        );

        log::info!("[ROUTER] Socket creation completed.");

        // Init channels — panic if they're already set
        let (tx_corosync_channel, mut rx_corosync_channel) = mpsc::channel::<Vec<u8>>(32);
        MLS_HANDSHAKE_CHANNEL
            .set(tx_corosync_channel)
            .expect("MLS_HANDSHAKE_CHANNEL already initialized");

        let (tx_corosync_signal, mut rx_corosync_signal) = mpsc::channel::<CorosyncSignal>(16);
        SIG_CHANNEL
            .set(tx_corosync_signal)
            .expect("SIG_CHANNEL already initialized");

        // Start Corosync thread — panic if it fails
        let handle_clone = self.corosync_handle.clone();
        thread::spawn(move || {
            if let Err(e) = receive_message(&handle_clone) {
                panic!(
                    "[ROUTER] Fatal: Error in Corosync message thread (receive_message): {:?}",
                    e
                );
            }
        });

        // Start update cycle ticker
        let mut update_interval = tokio::time::interval(Duration::from_secs(
            self.mls_group_handler.update_interval_secs(),
        ));

        loop {
            select! {
                biased;
                //  MLS commit messages coming from Corosync being sent to MLS_group_handler for processing
                Some(data) = rx_corosync_channel.recv() => {
                    log::debug!("[ROUTER] Corosync → MLS: Received {} bytes", data.len());

                    match self
                        .mls_group_handler
                        .process_incoming_delivery_service_message(&data)
                    {
                        Ok(Some((commit, welcome))) => {
                            try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                            try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                        }
                        Ok(None) => {
                            log::debug!("[ROUTER] No Commit or Welcome generated.");
                        }
                        Err(MlsEngineError::TrailingEpoch) => {
                            if self.wrong_epoch_timer.is_none() {
                                log::warn!("[ROUTER] Detected WrongEpoch. Starting recovery timer.");
                                self.wrong_epoch_timer = Some(Instant::now());
                            }
                        }
                        Err(e) => {
                            log::error!("[ROUTER] Error processing delivery service message: {}", e);
                        }
                    }
                }

                // (Totem) Corosync Membership changes
                Some(signal) = rx_corosync_signal.recv() => {
                    match signal {
                        CorosyncSignal::NodeJoined(node_ids) => {
                            log::info!("[ROUTER] Node(s) joined: {:?}", node_ids);
                        }

                        CorosyncSignal::NodeLeft(node_ids) => {
                            log::debug!("[ROUTER] Node(s) left: {:?}", node_ids);
                            if !node_ids.is_empty() {
                                self.mls_group_handler.schedule_removal(
                                    node_ids.into_iter().map(Into::into).collect()
                                );
                                log::info!("[ROUTER] Scheduled removal for left nodes.");
                            }
                        }

                        CorosyncSignal::GroupStatus(group) => {
                            log::debug!("[ROUTER] Group status update: {:?}", group);
                            self.mls_group_handler.update_totem_group(
                                group.into_iter().map(Into::into).collect()
                            );
                        }
                    }
                }

                // Used for testing
                // Commands coming from CMD-socket.
                Ok((size, src, buf)) = async {
                    let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                    let (size, src) = rx_cmd_socket.recv_from(&mut buf).await?;
                    Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE])>
                } => {
                    log::debug!("[ROUTER] CMD → MLS: Received {} bytes from {}", size, src);

                    match parse_command(&buf[..size]) {
                        Ok(Command::Add { key_package_bytes }) => {
                            log::debug!("[ROUTER] Add command received ({} bytes)", key_package_bytes.len());

                            let (commit, welcome) = self.mls_group_handler
                                .add_new_member_from_bytes(&key_package_bytes);

                            try_send!(&self.corosync_handle, "Commit", commit.as_slice());

                            try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                        }

                        Ok(Command::AddPending) => {
                            log::debug!("[ROUTER] AddPending command received.");

                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((commit, welcome))) => {
                                    log::info!("[ROUTER] AddPending: Commit and Welcome generated.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                }
                                Ok(None) => {
                                    log::debug!("[ROUTER] No key packages to add.");
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error during AddPending: {}", e);
                                }
                            }
                        }

                        Ok(Command::Remove { index }) => {
                            log::debug!("[ROUTER] Remove command received (index {}).", index);

                            let (commit, _welcome_option) = self
                                .mls_group_handler
                                .remove_member(LeafNodeIndex::new(index));

                            try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                        }

                        Ok(Command::Update) => {
                            log::debug!("[ROUTER] Update command received.");
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_option)) => {
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    if let Some(welcome) = welcome_option {
                                        try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                    }
                                }
                                Err(e) => {
                                    log::error!("Update command failed: {}", e);
                                }
                            }
                        }

                        Ok(Command::RetrieveRatchetTree) => {
                            log::debug!("[ROUTER] RetrieveRatchetTree command received (not implemented).");
                        }

                        Ok(Command::BroadcastKeyPackage) => {
                            log::debug!("[ROUTER] BroadcastKeyPackage command received.");
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {
                                    try_send!(&self.corosync_handle, "KeyPackage", key_package.as_slice());
                                }
                                Err(e) => {
                                    log::error!("Failed to retrieve KeyPackage: {}", e);
                                }
                            }
                        }

                        Ok(Command::ApplicationMsg { data }) => {
                            log::debug!("[ROUTER] ApplicationMsg command received ({} bytes)", data.len());
                            match self.mls_group_handler.process_outgoing_application_message(&data) {
                                Ok(out) => {
                                    if let Err(e) = tx_network_socket
                                        .send_to(out.as_slice(), format!("{}:{}", self.config.multicast_ip, self.config.multicast_port))
                                        .await
                                        .context("Failed to forward packet to network")
                                    {
                                        log::error!("[ROUTER] Failed to forward ApplicationMsg: {:?}", e);
                                    }
                                }
                                Err(e) => {
                                    log::error!("[ROUTER] Error processing ApplicationMsg: {}", e);
                                }
                            }
                        }

                        Err(e) => {
                            log::error!("[ROUTER] Failed to parse command: {}", e);
                        }
                    }
                }

              // Encrypted AppData coming in from radio network, being sent to MLS_group_handler for decryption,
              //then forwarded to Application
              Ok((size, src, buf)) = async {
                let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                let (size, src) = rx_network_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE]), anyhow::Error>
            } => {
                log::debug!("[ROUTER] Network → MLS: Received {} bytes from {}", size, src);

                match self.mls_group_handler.process_incoming_network_message(&buf[..size]) {
                    Ok(data) => {
                        self.wrong_epoch_timer = None;

                        if let Err(e) = tx_app_socket
                            .send_to(data.as_slice(), &self.config.tx_app_sock_addr)
                            .await
                            .with_context(|| {
                                format!(
                                    "Failed to send decrypted data to application at {}",
                                    self.config.tx_app_sock_addr
                                )
                            })
                        {
                            log::error!("[ROUTER] Error forwarding packet to application: {:?}", e);
                        }
                    }

                    Err(MlsEngineError::TrailingEpoch) | Err(MlsEngineError::ValidationError(_)) => {
                        if self.wrong_epoch_timer.is_none() {
                            log::warn!("[ROUTER] Detected WrongEpoch. Starting recovery timer.");
                            self.wrong_epoch_timer = Some(Instant::now());
                        }
                    }

                    Err(e) => {
                        log::error!("[ROUTER] Error processing network message from {}: {}", src, e);
                    }
                }
            }

            // Unencrypted AppData coming in from application, being sent to MLS_group_handler for encryption, then forwarded to radio network.
            Ok((size, src, buf)) = async {
                let mut buf = [0u8; MLS_MSG_BUFFER_SIZE];
                let (size, src) = rx_app_socket.recv_from(&mut buf).await?;
                Ok((size, src, buf)) as Result<(usize, SocketAddr, [u8; MLS_MSG_BUFFER_SIZE]), anyhow::Error>
            } => {
                log::debug!(
                    "[ROUTER] Application → MLS: Received {} bytes from {}",
                    size,
                    src
                );

                match self.mls_group_handler.process_outgoing_application_message(&buf[..size]) {
                    Ok(data) => {
                        let target_addr = format!("{}:{}", self.config.multicast_ip, self.config.multicast_port);

                        if let Err(e) = tx_network_socket
                            .send_to(data.as_slice(), &target_addr)
                            .await
                            .with_context(|| format!("Failed to send encrypted packet to {}", target_addr))
                        {
                            log::error!("[ROUTER] Failed to forward encrypted AppData: {:?}", e);
                        }
                    }

                    Err(e) => {
                        log::error!(
                            "[ROUTER] Failed to encrypt application data from {}: {}",
                            src,
                            e
                        );
                    }
                }
            }

                // Event loop: check for removals, adds and conduct updates based on current status.
                _ = update_interval.tick() => {
                    log::debug!("⏰ Scheduled Update Cycle scheduled self-update...");
                    if let Some(started_at) = self.wrong_epoch_timer {
                        if started_at.elapsed() >= self.wrong_epoch_timeout {
                            log::error!("WrongEpoch timer expired! Resetting MLS group.");
                            // Reset MLS and Corosync group.
                            self.mls_group_handler.reset_group();

                            self.wrong_epoch_timer = None; // Reset the timer after recovering
                        }
                    }
                    match self.mls_group_handler.get_mls_group_state() {
                        MlsSwarmState::Alone => {
                            // Add pending key packages
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((commit, welcome))) => {
                                    log::debug!("[ROUTER] Added pending key packages.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                }
                                Ok(None) => log::debug!("[ROUTER] No key packages to add."),
                                Err(e) => log::error!("[ROUTER] AddPending failed: {}", e),
                            }

                            // Broadcast own key package for dicovery
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {
                                    log::debug!("[ROUTER] Broadcasting key package.");
                                    try_send!(&self.corosync_handle, "KeyPackage", key_package.as_slice());
                                }
                                Err(e) => log::error!("[ROUTER] Failed to retrieve key package: {}", e),
                            }
                        }
                        MlsSwarmState::SubGroup => {
                            // Check for removals
                            if self.mls_group_handler.have_pending_removals() {
                                match self.mls_group_handler.remove_pending() {
                                    Ok((commit, welcome_opt)) => {
                                        log::info!("[ROUTER] ✅ Automatic removal succeeded.");
                                        try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                        if let Some(welcome) = welcome_opt {
                                            try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                        }
                                    }
                                    Err(e) => log::error!("❌ Automatic removal failed: {}", e),
                                }
                            }
                            // Add pending key packages
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((commit, welcome))) => {
                                    log::info!("[ROUTER] ✅ Added pending key packages.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                }
                                Ok(None) => log::debug!("[ROUTER] No key packages to add."),
                                Err(e) => log::error!("❌ AddPending failed: {}", e),
                            }
                            // Update own key material
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_opt)) => {
                                    log::info!("[ROUTER] ✅ Self-update successful.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    if let Some(welcome) = welcome_opt {
                                        try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                    }
                                }
                                Err(e) => log::error!("❌ Self-update failed: {}", e),
                            }
                            // Broadcast own key package for discovery
                            match self.mls_group_handler.get_key_package() {
                                Ok(key_package) => {
                                    log::info!("[ROUTER] Broadcasting key package (SubGroup).");
                                    try_send!(&self.corosync_handle, "KeyPackage", key_package.as_slice());
                                }
                                Err(e) => log::error!("❌ Failed to retrieve key package: {}", e),
                            }
                        }

                        MlsSwarmState::MainGroup => {
                            // Check for removals
                            if self.mls_group_handler.have_pending_removals() {
                                match self.mls_group_handler.remove_pending() {
                                    Ok((commit, welcome_opt)) => {
                                        log::info!("[ROUTER] ✅ Automatic removal succeeded.");
                                        try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                        if let Some(welcome) = welcome_opt {
                                            try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                        }
                                    }
                                    Err(e) => log::error!("❌ Automatic removal failed: {}", e),
                                }
                            }
                            // Add pending key packages
                            match self.mls_group_handler.add_pending_key_packages() {
                                Ok(Some((commit, welcome))) => {
                                    log::info!("[ROUTER] ✅ Added pending key packages.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                }
                                Ok(None) => log::debug!("[ROUTER] No key packages to add."),
                                Err(e) => log::error!("❌ AddPending failed: {}", e),
                            }
                            // Update own key material
                            match self.mls_group_handler.update_self() {
                                Ok((commit, welcome_opt)) => {
                                    log::info!("[ROUTER] ✅ Self-update successful.");
                                    try_send!(&self.corosync_handle, "Commit", commit.as_slice());
                                    if let Some(welcome) = welcome_opt {
                                        try_send!(&self.corosync_handle, "Welcome", welcome.as_slice());
                                    }
                                }
                                Err(e) => log::error!("❌ Self-update failed: {}", e),
                            }

                            // NOTE: No key package broadcast here
                        }
                    }
                }

                // Handle Ctrl+C (Shutdown)
                _ = signal::ctrl_c() => {
                    println!("\n🛑 Ctrl+C detected! Shutting down gracefully...");

                    match rust_corosync::cpg::finalize(self.corosync_handle) {
                        Ok(_) => {
                            log::info!("[ROUTER] Corosync finalized successfully.");
                        }
                        Err(e) => {
                            log::error!("[ROUTER] Failed to finalize Corosync: {}", e);
                        }
                    }

                    log::info!("[ROUTER] Shutdown complete. Exiting main loop.");
                    break;
                }

            }
        }
        log::info!("Router main loop exited.");
        Ok(())
    }
}
