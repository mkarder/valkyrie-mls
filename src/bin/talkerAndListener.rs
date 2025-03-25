use rust_corosync::cpg;
use rust_corosync::cpg::{Address, Guarantee, Handle, Model1Data, Model1Flags, ModelData};
use rust_corosync::{DispatchFlags, NodeId};
use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {


    let handle = initialize();

    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();


    // Join the group
    join_group(&handle, "my_test_group")?;

    println!("got here.");

    let sender_thread = thread::spawn(move || loop {
        if let Err(e) = cpg::dispatch(handle, DispatchFlags::OneNonblocking) {
            eprintln!("Dispatch error: {}", e);
        }
    });

    let receiver_thread = thread::spawn(move || {
        loop {
            // Sending Thread (Sends internal messages to the group)
            let message = "Hello, group!";
            if let Err(e) = send_message(&handle, message) {
                eprintln!("Failed to send message: {}", e);
            }
        }
    });

    sender_thread.join().unwrap();
    receiver_thread.join().unwrap();

    Ok(())
}

/// Callback function for received messages
fn deliver_callback(
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
    if let Ok(text) = std::str::from_utf8(msg) {
        println!("  Message content: {}", text);
    } else {
        println!("  Message bytes: {:?}", msg);
    }
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
    let handle = cpg::initialize(&ModelData::ModelV1(model1), 0)
        .expect("Failed to initialize CPG");
    
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
    let group_name = "my_test_group";
    let message_bytes = message.as_bytes();
    cpg::mcast_joined(*handle, Guarantee::TypeAgreed, message_bytes)?;
    println!("Sent message to group \"{}\": \"{}\"", group_name, message);
    Ok(())
}
