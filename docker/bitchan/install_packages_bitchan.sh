#!/bin/bash
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt update

apt install -yq --no-install-suggests --no-install-recommends \
    ca-certificates git nano wget

apt install -yq --no-install-suggests --no-install-recommends \
    build-essential curl secure-delete gnupg2 libsm6 libxext6 \
    netbase libcurl4-openssl-dev libjpeg-dev zlib1g-dev \
    python3 python3-dev python3-pip python3-venv \
    ffmpeg libavformat-dev libavcodec-dev libavcodec-extra libswscale-dev procps

# Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $(. /etc/os-release && echo "$VERSION_CODENAME")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
apt update
apt install -yq --no-install-suggests --no-install-recommends \
    docker-ce-cli


# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
