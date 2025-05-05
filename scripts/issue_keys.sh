#!/bin/bash

# Ensure ca.priv and ca.pub are present in the authentication/keys directory 
set -e

CA="7777"
NODES=( "2" "3" "4")

mkdir -p authentication/keys

for node in "${NODES[@]}"; do
  echo "🔐 Generating keys for $node..."

  openssl genpkey -algorithm Ed25519 -outform DER -out authentication/keys/$node.priv
  openssl pkey -in authentication/keys/$node.priv -inform DER -pubout -outform DER -out authentication/keys/$node.pub
done

for node in "${NODES[@]}"; do
  echo "📜 Issuing credential for $node..."
  cargo run --bin issue_ed25519_credential "$CA" "$node"
done

echo "✅ Done issuing all credentials."
