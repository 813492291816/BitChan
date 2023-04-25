#!/bin/bash
set -o pipefail

export TORVER=tor-0.4.7.9
export DEBIAN_FRONTEND=noninteractive

apt update

# Bitmessage apt dependencies
apt install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-setuptools libssl-dev fakeroot sed git \
    build-essential cmake libcap-dev libc-dev crudini wget

wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue --no-check-certificate https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py

# BitChan apt dependencies
apt install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 ffmpeg libsm6 libxext6 docker.io \
    nano netbase libcurl4-openssl-dev libjpeg-dev python3-dev python3-opencv python3-pip zlib1g-dev

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
