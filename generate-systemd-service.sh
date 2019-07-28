#!/bin/bash

BASE_URL="${BASE_URL:-http://localhost:9999}"
BINARY_PATH="${BINARY_PATH:-/usr/bin/share}"
RUN_DIR="${RUN_DIR:-/srv/share}"

cat <<-EOF
[Unit]
Description=share - simple filesharing service

[Service]
ExecStart=BASE_URL=$BASE_URL $BINARY_PATH

[Install]
WantedBy=multi-user.target
EOF
