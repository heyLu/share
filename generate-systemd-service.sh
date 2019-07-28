#!/bin/bash

BASE_URL="${BASE_URL:-http://localhost:9999}"
BINARY_PATH="${BINARY_PATH:-/usr/bin/share}"
RUN_DIR="${RUN_DIR:-/srv/share}"
UPLOADS_DIR="${UPLOADS_DIR:-$RUN_DIR/uploads}"

cat <<-EOF
[Unit]
Description=share - simple filesharing service

[Service]
ExecStart=BASE_URL=$BASE_URL $BINARY_PATH
ProtectSystem=strict
ReadWritePaths=$UPLOADS_DIR
ReadOnlyPaths=$RUN_DIR/upload-secret.txt $RUN_DIR/admin-secret.txt $RUN_DIR/validation.js

[Install]
WantedBy=multi-user.target
EOF
