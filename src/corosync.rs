use crate::router::TX_CHANNEL;
use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::NodeId;

/// Callback function for received multicast messages from Corosync 
pub fn deliver_callback(
    _handle: &Handle,
    group_name: String,
    nodeid: NodeId,
    pid: u32,
    msg: &[u8],
    msg_len: usize,
) {
    log::info!(
        "[Corosync] Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}",
        group_name, nodeid, pid, msg_len
    );

    if let Some(tx) = TX_CHANNEL.get() {
        let msg_vec = msg.to_vec();
        if let Err(e) = tx.try_send(msg_vec) {
            log::error!("[Corosync] Failed to forward message via TX_CHANNEL: {}", e);
        }
    } else {
        log::warn!("[Corosync] TX_CHANNEL not initialized, dropping message");
    }
    
}

/// Callback for membership changes
pub fn confchg_callback(
    _handle: &Handle,
    group_name: &str,
    member_list: Vec<Address>,
    left_list: Vec<Address>,
    joined_list: Vec<Address>,
) {
    log::info!("[Corosync] Confchg callback: Group \"{}\" membership changed.", group_name);
    log::info!("  Current members: {} node(s)", member_list.len());

    if !joined_list.is_empty() {
        log::info!("  Nodes joined: {:?}", joined_list);
    }
    if !left_list.is_empty() {
        log::info!("  Nodes left: {:?}", left_list);
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

    join_group(&handle, "my_test_group")
        .expect("[Corosync] Failed to join group");

    log::info!("[Corosync] initialized with group \"my_test_group\".");
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
    }
    log::info!("[Corosync] Sent message to group: {:?}", message);
    Ok(())
}

/// Blocking receive loop for Corosync messages (runs in a separate thread)
pub fn receive_message(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::dispatch(*handle, rust_corosync::DispatchFlags::Blocking) {
        eprintln!("Dispatch error: {}", e);
    }
    log::info!("Got eggs");

    Ok(())
}

