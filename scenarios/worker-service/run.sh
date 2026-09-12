#!/bin/sh
set -eu

echo "worker starting"
date > /data/heartbeat.txt
echo "worker ready"

sleep 3600
