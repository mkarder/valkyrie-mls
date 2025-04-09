#!/bin/bash

set -e

SESSION="test-3-drones-with-commando"

#Build the rust project
cargo build

# Start Docker containers
docker-compose down
docker-compose up -d
docker cp $HOME/valkyrie-mls/target/debug/valkyrie-mls node2:/valkyrie-mls/valkyrie-mls
docker cp $HOME/valkyrie-mls/target/debug/valkyrie-mls node3:/valkyrie-mls/valkyrie-mls
docker cp $HOME/valkyrie-mls/target/debug/valkyrie-mls node4:/valkyrie-mls/valkyrie-mls

# Wait a moment to let containers start up
sleep 2

# Kill only the specific tmux session if it exists
tmux has-session -t $SESSION 2>/dev/null && tmux kill-session -t $SESSION

# Start new detached tmux session
tmux new-session -d -s $SESSION

# Split windows: layout as 2x2 grid
tmux split-window -h -t $SESSION     # pane 1 (right)
tmux select-pane -t $SESSION:0.0
tmux split-window -v -t $SESSION     # pane 2 (bottom left)
tmux select-pane -t $SESSION:0.1
tmux split-window -v -t $SESSION     # pane 3 (bottom right)

# Send commands to each pane
tmux send-keys -t $SESSION:0.0 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $SESSION:0.0 'cd valkyrie-mls && ./valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.1 'docker exec --privileged -it node3 bash' C-m
tmux send-keys -t $SESSION:0.1 'cd valkyrie-mls && ./valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.2 'docker exec --privileged -it node4 bash' C-m
tmux send-keys -t $SESSION:0.2 'cd valkyrie-mls && ./valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.3 'RUST_LOG=debug ~/valkyrie-mls/target/debug/command' C-m

# Focus top-left pane and attach
tmux select-pane -t $SESSION:0.3
tmux attach-session -t $SESSION
