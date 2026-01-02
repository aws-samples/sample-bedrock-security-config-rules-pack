#!/bin/bash

# Redeploy script - runs cleanup and deploy in sequence
set -e

echo "Starting redeploy process..."

echo "Running cleanup..."
echo "yes" | ./scripts/cleanup.sh

echo "Running deploy..."
./scripts/deploy.sh --bucket bedrock-security-configrules-pack

echo "Redeploy complete!"
