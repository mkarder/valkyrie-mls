#!/bin/bash

SESSION="test-3-drones-with-commando"

# Start new detached tmux session
tmux new-session -d -s $SESSION

# Split the initial pane vertically (ctrl-b %)
tmux split-window -h -t $SESSION:0

# Split pane 0 horizontally (ctrl-b ")
tmux select-pane -t $SESSION:0.0
tmux split-window -v -t $SESSION:0.0

# Split pane 1 horizontally (ctrl-b ")
tmux select-pane -t $SESSION:0.1
tmux split-window -v -t $SESSION:0.1

#Commands
tmux send-keys -t $SESSION:0.0 'docker exec --privileged -it node2 bash' C-m
tmux send-keys -t $SESSION:0.0 'cd valkyrie-mls/' C-m
tmux send-keys -t $SESSION:0.0 './valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.1 'docker exec --privileged -it node3 bash' C-m
tmux send-keys -t $SESSION:0.1 'cd valkyrie-mls/' C-m
tmux send-keys -t $SESSION:0.1 './valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.2 'docker exec --privileged -it node4 bash' C-m
tmux send-keys -t $SESSION:0.2 'cd valkyrie-mls/' C-m
tmux send-keys -t $SESSION:0.2 './valkyrie-mls' C-m

tmux send-keys -t $SESSION:0.3 '~/valkyrie-mls/target/debug/command' C-m

# Focus top-left pane and attach
tmux select-pane -t $SESSION:0.0
tmux attach-session -t $SESSION