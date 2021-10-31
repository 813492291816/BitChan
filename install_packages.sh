#!/bin/bash
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update

# Bitmessage apt dependencies
apt-get install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-pip python-setuptools libssl-dev fakeroot sed git \
    build-essential cmake libcap-dev libc-dev

# BitChan apt dependencies
apt-get install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 ffmpeg libsm6 libxext6 docker.io \
    netbase libcurl4-openssl-dev libjpeg-dev zlib1g-dev

# Delete cached files
apt-get clean
rm -rf /var/lib/apt/lists/*
