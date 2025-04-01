use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::NodeId;
use crate::router::TX_CHANNEL;
use tokio::task;



/// Callback function for received messages
pub fn deliver_callback(
    _handle: &Handle,
    group_name: String,
    nodeid: NodeId,
    pid: u32,
    msg: &[u8],
    msg_len: usize,
) {
    println!(
        "Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}",
        group_name, nodeid, pid, msg_len
    );

    if let Some(tx) = TX_CHANNEL.get() {
        let msg_vec = msg.to_vec();
        let tx = tx.clone();
        task::spawn(async move {
            if let Err(e) = tx.send(msg_vec).await {
                eprintln!("Failed to send message through channel: {}", e);
            }
        });
    } else {
        eprintln!("TX_CHANNEL not initialized");
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
    println!(
        "Confchg callback: Group \"{}\" membership changed.",
        group_name
    );
    println!("  Current members: {} node(s)", member_list.len());
    if !joined_list.is_empty() {
        println!("  Nodes joined: {:?}", joined_list);
    }
    if !left_list.is_empty() {
        println!("  Nodes left: {:?}", left_list);
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

    join_group(&handle, "my_test_group").expect("Failed to join group");

    println!("CPG initialized.");

    handle
}

/// Function to join a group
pub fn join_group(handle: &Handle, group_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    //let group_name = "my_test_group";
    cpg::join(*handle, group_name)?;
    println!("Joined group \"{}\".", group_name);
    Ok(())
}

pub fn send_message(handle: &Handle, message: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::mcast_joined(*handle, Guarantee::TypeAgreed, message) {
        eprintln!("Failed to send message: {}", e);
    }
    // You can decide how you want to display the bytes. This prints them in debug format:
    println!("Sent message to group: {:?}", message);
    Ok(())
}

// Function to receive a message
// Note: DispatchFlags can be set to OneNonBlocking, One, All, or Blocking
pub fn receive_message(handle: &Handle) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::dispatch(*handle, rust_corosync::DispatchFlags::Blocking) {
        eprintln!("Dispatch error: {}", e);
    }
    Ok(())
}
