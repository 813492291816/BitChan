#!/bin/bash
set -o pipefail

export DEBIAN_FRONTEND=noninteractive

apt update
apt install -yq --no-install-suggests --no-install-recommends ca-certificates

wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue -O get-pip2.py https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip2.py

python2 -m pip install --no-cache-dir --upgrade pip

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
