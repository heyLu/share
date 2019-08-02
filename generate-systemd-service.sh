#!/bin/bash

BASE_URL="${BASE_URL:-http://localhost:9999}"
BINARY_PATH="${BINARY_PATH:-/usr/local/bin/share}"
RUN_DIR="${RUN_DIR:-/var/lib/share}"
UPLOADS_DIR="${UPLOADS_DIR:-$RUN_DIR/uploads}"
RUN_USER="${RUN_USER:-uploads}"
RUN_GROUP="${RUN_GROUP:-uploads}"

cat <<-EOF
[Unit]
Description=share - simple filesharing service

[Service]
User=$RUN_USER
Group=$RUN_GROUP
Environment=BASE_URL=$BASE_URL 
ExecStart=$BINARY_PATH
ProtectSystem=strict
ReadWritePaths=$UPLOADS_DIR
ReadOnlyPaths=$RUN_DIR/upload-secret.txt $RUN_DIR/admin-secret.txt $RUN_DIR/validation.js $BINARY_PATH
#SystemCallFilter=@file-system 
# @sync
RuntimeDirectory=share
StateDirectory=share/uploads
StateDirectoryMode=0750
WorkingDirectory=$RUN_DIR

[Install]
WantedBy=multi-user.target
EOF
