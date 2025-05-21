#!/bin/bash

set -e

TEST_SCRIPT="./start_test-3-drones-with-commando.sh"
LOG_BASE_DIR=~/valkyrie-mls/test-results/network-testing
WAIT_DURATION=660  # seconds; matches the timeout in your test script
NODES=("node2" "node3" "node4")

mkdir -p "$LOG_BASE_DIR"

for RUN in $(seq 2 10); do
    RUN_DIR="${LOG_BASE_DIR}/test-run-${RUN}"
    mkdir -p "$RUN_DIR"

    echo "🚀 Starting test run ${RUN}"

    for LOSS in $(seq 0 50); do
        echo "🌐 Starting test with ${LOSS}% packet loss"

        # Export LOSS so it is accessible in the test script
        export LOSS=$LOSS

        # Run your full test setup
        $TEST_SCRIPT

        echo "⏳ Waiting ${WAIT_DURATION}s for test to finish"
        #sleep $WAIT_DURATION

        RESULT_DIR="${RUN_DIR}/${LOSS}-loss"
        mkdir -p "$RESULT_DIR"

        echo "📦 Copying decryption logs for LOSS=${LOSS}% to ${RESULT_DIR}"
        for NODE in "${NODES[@]}"; do
            docker cp "${NODE}:/home/valkyrie-mls/decryption_stats.log" "${RESULT_DIR}/${NODE}_decryption_stats.log" || echo "❌ Failed to copy from $NODE"
        done

        echo "✅ Completed ${LOSS}% packet loss test for run ${RUN}"
        echo "----------------------------------------"
    done

    echo "✅✅ Completed test run ${RUN}"
    echo "========================================"
done

echo "🎉 All 10 test runs completed. Results saved in: $LOG_BASE_DIR"
