#!/bin/bash

set -e

SESSION="test-3-drones-with-commando"

# Start Docker containers
docker-compose down
docker-compose up -d


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

# Build and run Rust app in each container
tmux send-keys -t $SESSION:0.0 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $SESSION:0.0 'cd /root/valkyrie-mls && ./valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.1 'docker exec --privileged -it node3 bash' C-m
tmux send-keys -t $SESSION:0.1 'cd /root/valkyrie-mls && ./valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.2 'docker exec --privileged -it node4 bash' C-m
tmux send-keys -t $SESSION:0.2 'cd /root/valkyrie-mls && ./valkyrie-mls' C-m

# Run command tool locally
tmux send-keys -t $SESSION:0.3 'RUST_LOG=debug ~/valkyrie-mls/target/debug/command' C-m

# Focus top-left pane and attach
tmux select-pane -t $SESSION:0.3
tmux attach-session -t $SESSION
