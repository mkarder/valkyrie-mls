use std::thread;
use std::time::Duration;

use crate::router::{CorosyncSignal, MLS_HANDSHAKE_CHANNEL, SIG_CHANNEL};
use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::NodeId;

const GROUP: &str = "my_test_group";

/// Callback function for received multicast messages from Corosync
pub fn deliver_callback(
    _handle: &Handle,
    group_name: String,
    nodeid: NodeId,
    pid: u32,
    msg: &[u8],
    msg_len: usize,
) {
    //TODO make my_nodeid a more global variable
    let my_nodeid = std::env::var("NODE_ID")
        .expect("NODE_ID must be set")
        .parse::<u32>()
        .expect("NODE_ID must be a valid u64");
    let my_nodeid = NodeId::from(my_nodeid);

    if nodeid == my_nodeid {
        log::debug!(
            "[Corosync] Ignoring message from self (node ID: {})",
            nodeid
        );
        return;
    }

    log::debug!(
        "[Corosync] Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}",
        group_name,
        nodeid,
        pid,
        msg_len
    );

    if let Some(tx) = MLS_HANDSHAKE_CHANNEL.get() {
        let msg_vec = msg.to_vec();
        if let Err(e) = tx.try_send(msg_vec) {
            log::error!(
                "[Corosync] Failed to forward message via MLS_HANDSHAKE_CHANNEL: {}",
                e
            );
        }
    } else {
        log::warn!("[Corosync] MLS_HANDSHAKE_CHANNEL not initialized, dropping message");
    }
}

/// Callback for membership changes
pub fn confchg_callback(
    _handle: &Handle,
    _group_name: &str,
    members_list: Vec<Address>,
    left_list: Vec<Address>,
    joined_list: Vec<Address>,
) {
    log::info!("[Corosync] Nodes joined: {:?}", joined_list);
    log::info!("[Corosync] Nodes removed: {:?}", left_list);

    if let Some(sig_tx) = SIG_CHANNEL.get() {
        // Who left
        if !joined_list.is_empty() {
            let _ = sig_tx.try_send(CorosyncSignal::NodeJoined(
                joined_list.iter().map(|a| a.nodeid).collect(),
            ));
        }

        // Who joined
        if !left_list.is_empty() {
            let _ = sig_tx.try_send(CorosyncSignal::NodeLeft(
                left_list.iter().map(|a| a.nodeid).collect(),
            ));
        }

        // Inform MLS of current CPG (Totem) Group composition
        let group = members_list.iter().map(|a| a.nodeid).collect();
        let _ = sig_tx.try_send(CorosyncSignal::GroupStatus(group));
    }
}

pub fn initialize() -> cpg::Handle {
    // Define the model data
    let model1 = Model1Data {
        flags: Model1Flags::None,
        deliver_fn: Some(deliver_callback),
        confchg_fn: Some(confchg_callback),
        totem_confchg_fn: None,
    };

    // Initialize CPG
    let handle = cpg::initialize(&ModelData::ModelV1(model1), 0).expect("Failed to initialize CPG");

    join_group(&handle, GROUP).expect("[Corosync] Failed to join group");

    if let Some(sig_tx) = SIG_CHANNEL.get() {
        match cpg::membership_get(handle, "my_test_group") {
            Ok(members) => {
                // Inform MLS of current CPG (Totem) Group composition
                let group = members.iter().map(|a| a.nodeid).collect();
                let _ = sig_tx.try_send(CorosyncSignal::GroupStatus(group));
            }
            Err(e) => {
                log::error!(
                    "[Corosync] Could not obtain list of CPG (Totem) members because of {}",
                    e
                )
            }
        }
    }

    log::debug!("[Corosync] initialized with group \"my_test_group\".");
    handle
}

/// Joins a Corosync CPG group
pub fn join_group(handle: &Handle, group_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    cpg::join(*handle, group_name)?;
    log::info!("[Corosync] Joined group \"{}\".", group_name);
    Ok(())
}

/// Sends a multicast message to the currently joined group
pub fn send_message(handle: &Handle, message: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::mcast_joined(*handle, Guarantee::TypeAgreed, message) {
        eprintln!("Failed to send message: {}", e);
        return Err(Box::new(e));
    }
    log::debug!(
        "[Corosync] Sent message to group; msg_len={}",
        message.len()
    );
    Ok(())
}

/// Blocking receive loop for Corosync messages (runs in a separate thread)
pub fn receive_message(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::dispatch(*handle, rust_corosync::DispatchFlags::Blocking) {
        eprintln!("Dispatch error: {}", e);
        return Err(Box::new(e));
    }

    Ok(())
}

pub fn reset_group(handle: &Handle, delay_seconds: u32) -> Result<(), Box<dyn std::error::Error>> {
    cpg::leave(*handle, GROUP)?;

    // Wait for a delay
    thread::sleep(Duration::from_secs(delay_seconds as u64));

    cpg::join(*handle, GROUP)?;
    log::info!("[Corosync] Re-joined group \"{}\".", GROUP);
    Ok(())
}
