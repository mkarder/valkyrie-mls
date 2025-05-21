#!/bin/bash

set -e

CA="7777"
NODES=("2" "3" "4")
KEY_DIR="$HOME/valkyrie-mls/authentication/keys"

# Ensure the key directory exists
mkdir -p "$KEY_DIR"

# Generate CA keys if missing
if [[ ! -f "$KEY_DIR/$CA.priv" || ! -f "$KEY_DIR/$CA.pub" ]]; then
  echo "🔐 Generating CA keys for issuer ID $CA..."
  openssl genpkey -algorithm Ed25519 -outform DER -out "$KEY_DIR/$CA.priv"
  openssl pkey -in "$KEY_DIR/$CA.priv" -inform DER -pubout -outform DER -out "$KEY_DIR/$CA.pub"
else
  echo "✅ CA keys already exist at $KEY_DIR"
fi

# Generate keypairs for nodes
for node in "${NODES[@]}"; do
  echo "🔐 Generating keys for node $node..."
  openssl genpkey -algorithm Ed25519 -outform DER -out "$KEY_DIR/$node.priv"
  openssl pkey -in "$KEY_DIR/$node.priv" -inform DER -pubout -outform DER -out "$KEY_DIR/$node.pub"
done

# Change to project root so Rust sees correct relative paths (if needed)
cd "$HOME/valkyrie-mls"

# Issue credentials for each node
for node in "${NODES[@]}"; do
  echo "📜 Issuing credential for node $node..."
  cargo run --bin issue_ed25519_credential "$CA" "$node"
done

echo "✅ All credentials issued and keys generated successfully."
