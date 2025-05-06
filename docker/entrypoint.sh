#!/bin/bash
set -e  # Exit on error

echo "Starting $NODE_NAME with IP $NODE_IP"
echo "$NODE_NAME" > /etc/hostname
echo "127.0.0.1 localhost" > /etc/hosts
echo "$NODE_IP $NODE_NAME" >> /etc/hosts

echo "Starting Corosync..."
sudo corosync  # Start in background (-f = foreground, but we push it to background here)

cd /home/valkyrie-mls

exec "$@"  # This allows the script to pass additional arguments (like `bash`)
