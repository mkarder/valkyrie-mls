# valkyrie-mls
Implementation of OpenMLS for FFI's Valkyrie Swarm System.


## Overview 
The lab is setup using one host machine (running Ubuntu:latest), connected to the Jetson Nano over Ethernet. On the host machine we have several containers running.

### Directory overview
| Folder         | Description |
|---------------|------------------------------------------------------------|
| lab           | Root directory containing all project-related components. |
| ├─ corosync   | Official Corosync repository cloned from GitHub, used for group communication and cluster messaging. |
| ├─ corosync-app | Our custom implementation built on top of Corosync, providing a message delivery service. |
| ├─ docker     | Configuration and scripts for setting up a Docker-based network, simulating the distributed environment for testing. |
| └─ openmls    | OpenMLS repository cloned from GitHub, used for implementing and testing Messaging Layer Security (MLS) in our system. |




### Network configuration
A custom bridge network named `bridge_swarm` is created. This setup allows three nodes to communicate directly using static IPs on a custom bridge network. The `bridge_swarm` network acts as an isolated private network. The network is setup with the following settings: 
- Uses the bridge driver, which allows inter-container communication
- IP Address Management (IPAM)
	- The network has a subnet of `10.10.0.0/24`
	- The gateway is `10.10.0.1`, meaning containers will route traffic through this address 
- Bridge Network Driver Options 
	- `com.docker.network.bridge.name: "bridge_swarm"`
	- `com.docker.network.bridge.enable_ip_masquerade: "false"` Disables IP masquerading (prevents NAT translation)



| *Entitiy*       | *IP address*  |
| --------------- | ------------- |
| Network range   | `10.10.0.0/24` |
| Default gateway | `10.10.0.1`    |
| Host machine    | `10.10.0.1`    |
| Node *i*        | `10.10.0.i`    |
| Jetson Nano     | `10.0.0.100`  |

### Containers
The containers are built through the `Dockerfile`, an their individual names and IP addresses are defined in the `docker-compose.yaml`. They are all installed with basic network tools, like `ping`, `iperf3`, as well as `rust`, `openmls` and `corosync` installed. 

### Set up the lab
**Prerequisites**:
- Make sure the lab machine and the Jetson Nano is connected via Ethernet. 
	- `enp0s31f6` should be chosen as the physical interface on the *host*.
	- `eth0` should be set as the physical interface on the Jetson nano, with the IP address `10.0.0.100` added to the interface.

**How-to**:
1. Move into the `/home/lab/lab/docker` directory on the host machine.
2. Run `docker-compose build`, (if you have not built the images yet or have made changes to the Dockerfile). 
3. Start the containers and the netwwork with `docker-compose up -d`
4. Verify tht containers and the netowrk are running correctly with `docker ps`
4. Attach to one of the containers using `docker exec -it node2 bash`
5. Start Corosync (in the container or wherever it is required):  `corosync`. (Add flag `-f` to run in foreground, which will show you Corosync output in real-time.)   
 

## Corosync
### Start Corosync, configuration is determined through corosync.conf. Might have to use sudo to run with correct permissions  
 ```bash
   corosync
   ```

### Start Corosync in foreground 
 ```bash
   corosync -f
   ```


### Check if Corosync is running on the machine 
 ```bash
   ps aux | grep corosync
   ```

### Kill the Corosync process 
 ```bash
   pkill corosync
   ```

### See nodes connected over Corosync 
 ```bash
   corosync-cfgtool -s 
   ```




### Running Corosync-based Applications with Elevated Privileges
Corosync generally expects to be run as root or with elevated privileges because it relies on low-level system calls and shared-memory operations that require the right permissions. That’s why you see a “CsErrAccess” error when you run it as a normal user.

However, **building** and **running** your project under `sudo cargo ...` is not ideal. Instead, you typically want to:

The Corosync process need to be run 


1. **Build** as a normal user:

   ```bash
   cargo build
   ```

2. **Run** the compiled binary with sudo (or appropriate capabilities/permissions):
   ```bash
   sudo ./target/debug/corosync-app
   ```
