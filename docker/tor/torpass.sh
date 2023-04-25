#!/bin/bash

export TORPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)
echo "${TORPASS}" | dd of=/usr/local/tor/torpass
echo "HashedControlPassword $(tor --quiet --hash-password ${TORPASS})" | tee -a /usr/local/tor/torrc
TORPASS=""
