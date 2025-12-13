#!/bin/bash
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt update

apt install -yq --no-install-suggests --no-install-recommends \
    ca-certificates git nano wget

apt install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 libsm6 libxext6 docker.io \
    netbase libcurl4-openssl-dev libjpeg-dev zlib1g-dev \
    python3 python3-dev python3-pip python3-venv \
    ffmpeg libavformat-dev libavcodec-dev libavcodec-extra libswscale-dev procps

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
