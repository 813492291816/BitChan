#!/bin/bash
set -o pipefail

export TORVER=tor-0.4.7.9
export DEBIAN_FRONTEND=noninteractive

apt update

# Tor
apt install -yq --no-install-suggests --no-install-recommends \
    build-essential automake autoconf libevent-dev libssl-dev zlib1g-dev zlib1g liblzma-dev libzstd-dev pkg-config libnss3-dev wget

wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue -O /tmp/${TORVER}.tar.gz https://www.torproject.org/dist/${TORVER}.tar.gz \
&& cd /tmp \
&& tar xvzf ${TORVER}.tar.gz \
&& cd /tmp/${TORVER} \
&& ./configure --enable-nss \
&& make \
&& make install \
&& rm -rf /tmp/${TORVER}.tar.gz \
&& rm -rf /tmp/${TORVER}

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
