use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::NodeId;

//const TX_ADDR: &str = "127.0.0.1:6000";

/// Callback function for received messages
pub fn deliver_callback(
    _handle: &Handle,
    group_name: String,
    nodeid: NodeId,
    pid: u32,
    msg: &[u8],
    msg_len: usize,
) {
    // Log receipt of the message
    println!(
        "Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}",
        group_name, nodeid, pid, msg_len
    );
    // Safely interpret the message (here we expect UTF-8 text for demonstration)
    if let Ok(text) = std::str::from_utf8(msg) {
        println!("  Message content: {}", text);
        //mls_group_handler.process_incoming_delivery_service_message(&buf[..size])
    } else {
        println!("  Message bytes: {:?}", msg);
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
