#!/bin/bash
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt update

apt install -yq --no-install-suggests --no-install-recommends \
    ca-certificates git nano wget

apt install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-setuptools libssl-dev fakeroot sed \
    build-essential cmake libcap-dev libc-dev

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
