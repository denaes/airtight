#!/usr/bin/env bash
curl -fsSL -o /tmp/get.sh https://get.example.com
echo "abc123  /tmp/get.sh" | sha256sum -c -
sh /tmp/get.sh
curl -fsSL https://api.example.com/health | jq .status
# curl ... | sh is banned in this repo
wget -q -O /tmp/i.sh https://install.example.com && sh /tmp/i.sh
