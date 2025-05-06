#!/bin/bash

set -e

# Inside start_test-3-drones-with-commando.sh
echo "📶 Starting test with packet loss = ${LOSS}%"

SESSION="test-3-drones-with-commando"
LOG_SESSION="log-decryption-results"


# Start Docker containers
docker-compose down
docker-compose up -d

# Kill existing tmux sessions if they exist
tmux has-session -t $SESSION 2>/dev/null && tmux kill-session -t $SESSION
tmux has-session -t $LOG_SESSION 2>/dev/null && tmux kill-session -t $LOG_SESSION


# Start new detached tmux session
tmux new-session -d -s $SESSION

# Split windows: layout as 2x2 grid
tmux split-window -h -t $SESSION     # pane 1 (right)
tmux select-pane -t $SESSION:0.0
tmux split-window -v -t $SESSION     # pane 2 (bottom left)
tmux select-pane -t $SESSION:0.1
tmux split-window -v -t $SESSION     # pane 3 (bottom right)

# Start node2
tmux send-keys -t $SESSION:0.0 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $SESSION:0.0 'sudo corosync' C-m
sleep 3 # Necessary interval to not have syncing errors cause of updates
tmux send-keys -t $SESSION:0.0 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $SESSION:0.0 'timeout 630s sudo RUST_LOG=info HOME=/home NODE_ID=2 NODE_IP=10.10.0.2 ./valkyrie-mls' C-m
 

# Start node3
tmux send-keys -t $SESSION:0.1 'docker exec --privileged -it node3 bash' C-m
tmux send-keys -t $SESSION:0.1 'sudo corosync' C-m
sleep 3 
tmux send-keys -t $SESSION:0.1 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $SESSION:0.1 'timeout 630s sudo RUST_LOG=info HOME=/home NODE_ID=3 NODE_IP=10.10.0.3 ./valkyrie-mls' C-m


# Start node4
tmux send-keys -t $SESSION:0.2 'docker exec --privileged -it node4 bash' C-m
tmux send-keys -t $SESSION:0.2 'sudo corosync' C-m
sleep 3
tmux send-keys -t $SESSION:0.2 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $SESSION:0.2 'timeout 630s sudo RUST_LOG=info HOME=/home NODE_ID=4 NODE_IP=10.10.0.4 ./valkyrie-mls' C-m

# Run command tool locally
tmux send-keys -t $SESSION:0.3 'RUST_LOG=debug ~/valkyrie-mls/target/debug/command' C-m

# Focus commando pane and attach
tmux select-pane -t $SESSION:0.3

sleep 10 # Necessary interval to not have syncing errors cause of updates 


# === Create a second session for logging + adding 5% packet loss ===
tmux new-session -d -s $LOG_SESSION

# Split to 2x2 layout
tmux split-window -h -t $LOG_SESSION     # right pane
tmux select-pane -t $LOG_SESSION:0.0
tmux split-window -v -t $LOG_SESSION     # bottom left
tmux select-pane -t $LOG_SESSION:0.1
tmux split-window -v -t $LOG_SESSION     # bottom right

# node2: add 5% loss and tail log
tmux send-keys -t $LOG_SESSION:0.0 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $LOG_SESSION:0.0 "tc qdisc add dev eth0 root netem loss ${LOSS}%" C-m
tmux send-keys -t $LOG_SESSION:0.0 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $LOG_SESSION:0.0 'timeout 605s mgen input test.mgn' C-m

# node3: add 5% loss
tmux send-keys -t $LOG_SESSION:0.1 'docker exec --privileged -it node3 bash' C-m
tmux send-keys -t $LOG_SESSION:0.1 "tc qdisc add dev eth0 root netem loss ${LOSS}%" C-m
tmux send-keys -t $LOG_SESSION:0.1 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $LOG_SESSION:0.1 'timeout 605s mgen input test.mgn' C-m

# node4: add 5% loss
tmux send-keys -t $LOG_SESSION:0.2 'docker exec --privileged -it node4 bash' C-m
tmux send-keys -t $LOG_SESSION:0.2 "tc qdisc add dev eth0 root netem loss ${LOSS}%" C-m
tmux send-keys -t $LOG_SESSION:0.2 'cd /home/valkyrie-mls' C-m
tmux send-keys -t $LOG_SESSION:0.2 'timeout 605s mgen input test.mgn' C-m


# Attach to node2 for manual overview of logs
tmux send-keys -t $LOG_SESSION:0.3 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $LOG_SESSION:0.3 'cd /home/valkyrie-mls' C-m
tmux select-pane -t $LOG_SESSION:0.3

sleep 630
