#!/bin/bash

set -e

# Arguments
CRED_TYPE="$1"        # "basic" or "ed25519"
UPDATE_INTERVAL="$2"  # e.g., 10

if [[ -z "$CRED_TYPE" || -z "$UPDATE_INTERVAL" ]]; then
  echo "Usage: $0 <credential_type: basic|ed25519> <update_interval_secs: u16>"
  exit 1
fi

SESSION="automatic-add-and-remove-3-drones"

# Start Docker containers
docker-compose down
docker-compose up -d

# Kill existing tmux session if any
tmux has-session -t $SESSION 2>/dev/null && tmux kill-session -t $SESSION

# Start a new tmux session
tmux new-session -d -s $SESSION

# Layout: 2x2 grid of panes
tmux split-window -h -t $SESSION
tmux select-pane -t $SESSION:0.0
tmux split-window -v -t $SESSION
tmux select-pane -t $SESSION:0.1
tmux split-window -v -t $SESSION

# Define containers and assign corresponding node IDs
containers=(node2 node3 node4)
node_ids=(2 3 4)

for i in 0 1 2; do
  pane="0.$i"
  container="${containers[$i]}"
  node_id="${node_ids[$i]}"

  tmux send-keys -t $SESSION:$pane "docker exec --privileged -it $container bash" C-m

  # Overwrite the last 3 lines of config.toml
  tmux send-keys -t $SESSION:$pane "sed -i '\$d' /root/valkyrie-mls/config.toml" C-m
  tmux send-keys -t $SESSION:$pane "sed -i '\$d' /root/valkyrie-mls/config.toml" C-m
  tmux send-keys -t $SESSION:$pane "sed -i '\$d' /root/valkyrie-mls/config.toml" C-m

  # Append new config lines
  tmux send-keys -t $SESSION:$pane "echo 'node_id = $node_id' >> /root/valkyrie-mls/config.toml" C-m
  tmux send-keys -t $SESSION:$pane "echo 'credential_type = \"$CRED_TYPE\"' >> /root/valkyrie-mls/config.toml" C-m
  tmux send-keys -t $SESSION:$pane "echo 'update_interval_secs = $UPDATE_INTERVAL' >> /root/valkyrie-mls/config.toml" C-m

  # Move to valkyrie-folder
   tmux send-keys -t $SESSION:$pane "cd /root/valkyrie-mls" C-m
done

# Focus a pane and attach
tmux select-pane -t $SESSION:0.0
tmux attach-session -t $SESSION
