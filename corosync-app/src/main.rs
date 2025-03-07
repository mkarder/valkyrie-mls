use rust_corosync::cpg;
use rust_corosync::cpg::{Handle, Model1Data, Model1Flags, ModelData, Address, Guarantee};
use rust_corosync::{NodeId, DispatchFlags};
use std::io::{self, Write}; 

/// This callback is invoked for every message delivered to the group (including self-sent messages).
fn deliver_callback(_handle: &Handle, group_name: String, nodeid: NodeId, pid: u32, 
                    msg: &[u8], msg_len: usize) {
    // Log receipt of the message
    println!("Deliver callback: group=\"{}\", from node {:?} (pid {}), msg_len={}", 
             group_name, nodeid, pid, msg_len);
    // Safely interpret the message (here we expect UTF-8 text for demonstration)
    if let Ok(text) = std::str::from_utf8(msg) {
        println!("  Message content: {}", text);
    } else {
        println!("  Message bytes: {:?}", msg);
    }
}

/// This callback is invoked whenever the group membership changes (nodes join/leave).
fn confchg_callback(_handle: &Handle, group_name: &str, 
                    member_list: Vec<Address>, left_list: Vec<Address>, joined_list: Vec<Address>) {
    println!("Confchg callback: Group \"{}\" membership changed.", group_name);
    println!("  Current members: {} node(s)", member_list.len());
    if !joined_list.is_empty() {
        println!("  Nodes joined: {:?}", joined_list);
    }
    if !left_list.is_empty() {
        println!("  Nodes left: {:?}", left_list);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Prepare the Model1Data with our callbacks. We don't need totem_confchg_fn for this example.
    let model1 = Model1Data {
        flags: Model1Flags::None,
        deliver_fn: Some(deliver_callback),
        confchg_fn: Some(confchg_callback),
        totem_confchg_fn: None,
    };

    // Initialize the CPG API (Model V1) and obtain a handle
    let handle = cpg::initialize(&ModelData::ModelV1(model1), /*context=*/ 0)
        .expect("Failed to TEST initialize CPG");
    println!("CPG initialized.");

    loop {
        // Prompt the user for input
        print!("Enter a command (1, 2, 3, or 'quit'): ");
        io::stdout().flush()?; // Flush the prompt to ensure it's visible

        // Read the input line
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        // Match on the input to decide what to do
        match input {
            "1" => {
                println!("You pressed 1!");
                // Perform command 1 logic here
            },
            "2" => {
                println!("You pressed 2!");
                // Perform command 2 logic here
            },
            "3" => {
                println!("You pressed 3!");
                // Perform command 3 logic here
            },
            "quit" => {
                println!("Quitting the program...");
                break;
            },
            _ => {
                println!("Unknown command. Please enter 1, 2, 3, or 'quit'.");
            }
        }
    }

    Ok(())
}

    /*


    // Join a group to start receiving messages
    let group_name = "my_test_group";
    cpg::join(handle, group_name)?;
    println!("Joined group \"{}\".", group_name);

    // Dispatch any pending events (this will trigger confchg_callback for the join event)
    cpg::dispatch(handle, DispatchFlags::All)?;

    // Send a message to the group (this will also be delivered to ourselves)
    let message = b"Hello, CPG group!";
    cpg::mcast_joined(handle, Guarantee::TypeAgreed, message)?;
    println!("Sent message to group \"{}\".", group_name);

    // Dispatch events to process incoming messages (deliver_callback will be called)
    cpg::dispatch(handle, DispatchFlags::All)?;

    // Clean up: leave the group and finalize the CPG handle
    cpg::leave(handle, group_name)?;
    cpg::finalize(handle)?;
    println!("Left group and finalized CPG handle.");
    Ok(())
}
*/