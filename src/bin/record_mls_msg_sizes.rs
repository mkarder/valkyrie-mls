/*
Results from Marstrander:
Update              750 B
Commit              400 B
Add                 1100 B
Welcome             1700 B      2 members, no certificate
Welcome             19 000 B    10 members, no certificate
Key package         800 B       no certificate
X.509 certificate   2600 B
*/

use valkyrie_mls::config::MlsConfig;
use valkyrie_mls::mls_group_handler::{MlsEngine, MlsSwarmLogic};

fn main() {
    // two_basic_members();
    // two_ed25519_members();
    // for i in 2..=16 {
    //     n_basic_members(i);
    // }

    for i in 2..=16 {
        n_ed25519_members(i);
    }
}

/*
Results:
Key package: 282
Commit: 687
Welcome: 827
Update (node1): 489
Update (node2): 339
*/
#[allow(dead_code)]
fn two_basic_members() {
    // Instantiating two members and add them to the same group
    let config_1 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 1,
        update_interval_secs: 100,
    };

    let config_2 = MlsConfig {
        gcs_id: 1,
        credential_type: "Basic".to_string(),
        node_id: 2,
        update_interval_secs: 100,
    };

    let mut node1 = MlsEngine::new(config_1);
    let mut node2 = MlsEngine::new(config_2);

    let kp2 = node2.get_key_package().unwrap();
    println!("Key package: {:?}", kp2.len());

    node1
        .process_incoming_delivery_service_message(&kp2)
        .unwrap();

    let (commit, welcome) = node1
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected commit and welcome");

    println!("Commit: {:?}", commit.len());
    println!("Welcome: {:?}", welcome.len());

    let (update, _) = node1.update_self().unwrap();
    println!("Update 1: {:?}", update.len());
    let (update, _) = node2.update_self().unwrap();
    println!("Update 2: {:?}", update.len());
}

/*
Results
Key package: 407
Commit: 937
Welcome: 1077
Update 1: 614
Update 2: 464
*/
#[allow(dead_code)]
fn two_ed25519_members() {
    // Instantiating two members and add them to the same group
    let config_1 = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 7777,
        update_interval_secs: 100,
    };

    let config_2 = MlsConfig {
        gcs_id: 1,
        credential_type: "ed25519".to_string(),
        node_id: 8888,
        update_interval_secs: 100,
    };

    let mut node1 = MlsEngine::new(config_1);
    let mut node2 = MlsEngine::new(config_2);

    let kp2 = node2.get_key_package().unwrap();
    println!("Key package: {:?}", kp2.len());

    node1
        .process_incoming_delivery_service_message(&kp2)
        .unwrap();

    let (commit, welcome) = node1
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected commit and welcome");

    println!("Commit: {:?}", commit.len());
    println!("Welcome: {:?}", welcome.len());

    let (update, _) = node1.update_self().unwrap();
    println!("Update 1: {:?}", update.len());
    let (update, _) = node2.update_self().unwrap();
    println!("Update 2: {:?}", update.len());
}

/*
Key package for node 2: 282 bytes
...
Key package for node 10: 282 bytes
Commit (adding 9 members): 3038 bytes
Welcome (10 members total): 3663 bytes
Update from node 1: 1250 bytes
Update from node 2: 339 bytes
Update from node 3: 339 bytes
...
Update from node 10: 339 bytes
*/
#[allow(dead_code)]
fn n_basic_members(n: usize) {
    // Instantiate all n members (node_id 1 to n)
    println!("\n### Testing {} members ###", n);
    let mut nodes: Vec<MlsEngine> = (1..=n)
        .map(|id| {
            MlsEngine::new(MlsConfig {
                gcs_id: 1,
                credential_type: "Basic".to_string(),
                node_id: id as u32,
                update_interval_secs: 100,
            })
        })
        .collect();

    // Node 1 is the group initiator
    let mut node1 = nodes.remove(0);

    // Get key packages for the other n-1 members
    let key_packages: Vec<_> = nodes
        .iter_mut()
        .enumerate()
        .map(|(_i, node)| {
            let kp = node.get_key_package().unwrap();
            // println!("Key package for node {}: {} bytes", i + 2, kp.len());
            kp
        })
        .collect();

    // Node 1 processes all key packages
    for kp in &key_packages {
        node1
            .process_incoming_delivery_service_message(kp)
            .expect("Failed to process KP");
    }

    // Node 1 commits the pending adds
    let (commit, welcome) = node1
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected commit and welcome");

    println!("Commit (adding {} members): {} bytes", n - 1, commit.len());
    println!("Welcome ({} members total): {} bytes", n, welcome.len());

    // Simulate updates from node 1 and node 2 (the first two in the group)
    let (update1, _) = node1.update_self().unwrap();
    println!("Update from node 1: {} bytes", update1.len());

    // for node in &mut nodes {
    //     let (update, _) = node.update_self().unwrap();
    //     print!("Update: {} bytes\n", update.len());
    // }
}


/*
### Testing 2 ed25519 members ###
Key package for node 2: 407 bytes
Commit (adding 1 members): 937 bytes
Welcome (2 members total): 1077 bytes
Update from node 1: 614 bytes
Update from node 2: 464 bytes

### Testing 3 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Commit (adding 2 members): 1378 bytes
Welcome (3 members total): 1599 bytes
Update from node 1: 731 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes

### Testing 4 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Commit (adding 3 members): 1784 bytes
Welcome (4 members total): 2053 bytes
Update from node 1: 813 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes

### Testing 5 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Commit (adding 4 members): 2224 bytes
Welcome (5 members total): 2575 bytes
Update from node 1: 930 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes

### Testing 6 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Commit (adding 5 members): 2630 bytes
Welcome (6 members total): 3029 bytes
Update from node 1: 1012 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes

### Testing 7 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Commit (adding 6 members): 3036 bytes
Welcome (7 members total): 3483 bytes
Update from node 1: 1094 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes

### Testing 8 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Commit (adding 7 members): 3442 bytes
Welcome (8 members total): 3937 bytes
Update from node 1: 1176 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes

### Testing 9 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Commit (adding 8 members): 3882 bytes
Welcome (9 members total): 4459 bytes
Update from node 1: 1293 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes

### Testing 10 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Commit (adding 9 members): 4288 bytes
Welcome (10 members total): 4913 bytes
Update from node 1: 1375 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes

### Testing 11 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Commit (adding 10 members): 4694 bytes
Welcome (11 members total): 5367 bytes
Update from node 1: 1457 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes

### Testing 12 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Key package for node 12: 407 bytes
Commit (adding 11 members): 5100 bytes
Welcome (12 members total): 5821 bytes
Update from node 1: 1539 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes
Update from node 12: 464 bytes

### Testing 13 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Key package for node 12: 407 bytes
Key package for node 13: 407 bytes
Commit (adding 12 members): 5506 bytes
Welcome (13 members total): 6275 bytes
Update from node 1: 1621 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes
Update from node 12: 464 bytes
Update from node 13: 464 bytes

### Testing 14 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Key package for node 12: 407 bytes
Key package for node 13: 407 bytes
Key package for node 14: 407 bytes
Commit (adding 13 members): 5912 bytes
Welcome (14 members total): 6729 bytes
Update from node 1: 1703 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes
Update from node 12: 464 bytes
Update from node 13: 464 bytes
Update from node 14: 464 bytes

### Testing 15 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Key package for node 12: 407 bytes
Key package for node 13: 407 bytes
Key package for node 14: 407 bytes
Key package for node 15: 407 bytes
Commit (adding 14 members): 6318 bytes
Welcome (15 members total): 7183 bytes
Update from node 1: 1785 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes
Update from node 12: 464 bytes
Update from node 13: 464 bytes
Update from node 14: 464 bytes
Update from node 15: 464 bytes

### Testing 16 ed25519 members ###
Key package for node 2: 407 bytes
Key package for node 3: 407 bytes
Key package for node 4: 407 bytes
Key package for node 5: 407 bytes
Key package for node 6: 407 bytes
Key package for node 7: 407 bytes
Key package for node 8: 407 bytes
Key package for node 9: 407 bytes
Key package for node 10: 407 bytes
Key package for node 11: 407 bytes
Key package for node 12: 407 bytes
Key package for node 13: 407 bytes
Key package for node 14: 407 bytes
Key package for node 15: 407 bytes
Key package for node 16: 407 bytes
Commit (adding 15 members): 6724 bytes
Welcome (16 members total): 7637 bytes
Update from node 1: 1867 bytes
Update from node 2: 464 bytes
Update from node 3: 464 bytes
Update from node 4: 464 bytes
Update from node 5: 464 bytes
Update from node 6: 464 bytes
Update from node 7: 464 bytes
Update from node 8: 464 bytes
Update from node 9: 464 bytes
Update from node 10: 464 bytes
Update from node 11: 464 bytes
Update from node 12: 464 bytes
Update from node 13: 464 bytes
Update from node 14: 464 bytes
Update from node 15: 464 bytes
Update from node 16: 464 bytes
*/

fn n_ed25519_members(n: usize) {
    println!("\n### Testing {} ed25519 members ###", n);

    // Instantiate all n members (node_id 1 to n)
    let mut nodes: Vec<MlsEngine> = (1..=n)
        .map(|id| {
            MlsEngine::new(MlsConfig {
                gcs_id: 1,
                credential_type: "ed25519".to_string(),
                node_id: id as u32,
                update_interval_secs: 100,
            })
        })
        .collect();

    // Node 1 is the group initiator
    let mut node1 = nodes.remove(0);

    // Get key packages from other nodes
    let key_packages: Vec<_> = nodes
        .iter_mut()
        .enumerate()
        .map(|(i, node)| {
            let kp = node.get_key_package().unwrap();
            println!("Key package for node {}: {} bytes", i + 2, kp.len());
            kp
        })
        .collect();

    // Node 1 processes all incoming key packages
    for kp in &key_packages {
        node1
            .process_incoming_delivery_service_message(kp)
            .expect("Failed to process key package");
    }

    // Node 1 commits the pending adds
    let (commit, welcome) = node1
        .add_pending_key_packages()
        .unwrap()
        .expect("Expected commit and welcome");

    println!("Commit (adding {} members): {} bytes", n - 1, commit.len());
    println!("Welcome ({} members total): {} bytes", n, welcome.len());

    // Update from node 1 (the initiator)
    let (update1, _) = node1.update_self().unwrap();
    println!("Update from node 1: {} bytes", update1.len());

    // Updates from the rest of the nodes

    for (i, node) in nodes.iter_mut().enumerate() {
        let (update, _) = node.update_self().unwrap();
        println!("Update from node {}: {} bytes", i + 2, update.len());
    }
}
