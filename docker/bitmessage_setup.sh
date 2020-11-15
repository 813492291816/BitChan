#!/bin/bash

APIPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)

if [ ! -f "/usr/local/bitmessage/keys.dat" ] ; then
  printf "\n+++ keys.dat not present. Creating.\n"
  cd /usr/local/bitmessage || return
  /usr/local/bin/pybitmessage -h

  sed -i '/apivariant/d' /usr/local/bitmessage/keys.dat \
  && sed -i 's/socksproxytype.*/socksproxytype = SOCKS5/' /usr/local/bitmessage/keys.dat \
  && sed -i 's/sockshostname.*/sockshostname = tor/' /usr/local/bitmessage/keys.dat \
  && sed -i 's/socksport.*/socksport = 9060/' /usr/local/bitmessage/keys.dat \
  && echo "apienabled = true" >> /usr/local/bitmessage/keys.dat \
  && echo "apiport = 8445" >> /usr/local/bitmessage/keys.dat \
  && echo "apiinterface = 0.0.0.0" >> /usr/local/bitmessage/keys.dat \
  && echo "apiusername = bitchan" >> /usr/local/bitmessage/keys.dat \
  && echo "apipassword = ${APIPASS}" >> /usr/local/bitmessage/keys.dat
else
  printf "\n+++ keys.dat present. Skipping.\n"
fi
