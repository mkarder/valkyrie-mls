use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::{DispatchFlags, NodeId};

pub struct Corosync {
    pub handle: Handle,
}

impl Corosync {
    pub fn new() -> Self {
        let handle = initialize();
        Corosync { handle }
    }


    /// Function to send a message
    pub fn send_message(
        &self,
        handle: &Handle,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(e) = cpg::mcast_joined(*handle, Guarantee::TypeAgreed, message) {
            eprintln!("Failed to send message: {}", e);
        }
        // You can decide how you want to display the bytes. This prints them in debug format:
        println!("Sent message to group: {:?}", message);
        Ok(())
    }

    /// Function to receive a message
    /// Note: DispatchFlags can be set to OneNonBlocking, One, All, or Blocking
    pub fn receive_message(&self, handle: Handle) -> Result<(), Box<dyn std::error::Error>> {
        if let Err(e) = cpg::dispatch(handle, DispatchFlags::OneNonblocking) {
            eprintln!("Dispatch error: {}", e);
        }
        Ok(())
    }
}

/// Callback function for received messages
fn deliver_callback<'a>(
    _handle: &Handle,
    group_name: String,
    nodeid: NodeId,
    pid: u32,
    msg: &'a [u8],
    msg_len: usize,
)-> &'a [u8] {
    println!(
        "Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}",
        group_name, nodeid, pid, msg_len
    );

    if let Ok(text) = std::str::from_utf8(msg) {
        println!("  Message content: {}", text);
    } else {
        println!("  Message bytes: {:?}", msg);
    }
    msg
}

/// Callback for membership changes
fn confchg_callback(
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

fn initialize() -> cpg::Handle {
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
fn join_group(handle: &Handle, group_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    //let group_name = "my_test_group";
    cpg::join(*handle, group_name)?;
    println!("Joined group \"{}\".", group_name);
    Ok(())
}

/// Function to send a message
fn send_message(handle: &Handle, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    let message_bytes: &[u8] = message.as_bytes();
    if let Err(e) = cpg::mcast_joined(*handle, Guarantee::TypeAgreed, message_bytes) {
        eprintln!("Failed to send message: {}", e);
    }
    println!("Sent message to group: \"{}\"", message);
    Ok(())
}

/// Function to receive a message
/// Note: DispatchFlags can be set to OneNonBlocking, One, All, or Blocking
fn receive_message(handle: Handle) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = cpg::dispatch(handle, DispatchFlags::OneNonblocking) {
        eprintln!("Dispatch error: {}", e);
    }
    Ok(())
}
