#!/bin/bash
set -o pipefail

TORPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)
export TORPASS

mkdir -p /usr/local/tor
mkdir -p /usr/local/tor/bm
mkdir -p /usr/local/tor/cus
mkdir -p /usr/local/tor/rand
mkdir -p /usr/local/tor/authorized_clients

if [ ! -f "/usr/local/tor/torrc" ] ; then
  cp /torrc /usr/local/tor

  echo "${TORPASS}" | dd of=/usr/local/tor/torpass
  echo "HashedControlPassword $(tor --quiet --hash-password "${TORPASS}")" | tee -a /usr/local/tor/torrc
  TORPASS=""

  chmod -R 700 /usr/local/tor
  chown -R root /usr/local/tor
fi
