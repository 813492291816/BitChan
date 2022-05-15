#!/bin/bash
set -o pipefail

export TORNAME=tor-0.4.7.7
export DEBIAN_FRONTEND=noninteractive

apt update

# Bitmessage apt dependencies
apt install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-setuptools libssl-dev fakeroot sed git \
    build-essential cmake libcap-dev libc-dev crudini wget

wget --no-check-certificate https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py

# BitChan apt dependencies
apt install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 ffmpeg libsm6 libxext6 docker.io \
    netbase libcurl4-openssl-dev libjpeg-dev python3-dev python3-opencv python3-pip zlib1g-dev

# Tor
apt install -yq --no-install-suggests --no-install-recommends \
    build-essential libwww-perl libevent-dev libssl-dev wget zlib1g

wget -qO - https://www.torproject.org/dist/${TORNAME}.tar.gz | tar xvz -C /tmp \
&& cd /tmp/${TORNAME} \
&& ./configure \
&& make \
&& make install \
&& rm -rf /tmp/${TORNAME}.tar.gz \
&& rm -rf /tmp/${TORNAME}

# Delete cached files
apt clean
rm -rf /var/lib/apt/lists/*
