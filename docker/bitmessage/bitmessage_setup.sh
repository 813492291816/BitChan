#!/bin/bash

APIUSER=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c12 && echo)
APIPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)

mkdir -p /usr/local/bitmessage

check_keys() {
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings socksport 9050
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionport 8444
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings sockslisten False
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionbindip 172.28.1.3
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings extport 8444
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apienabled True
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiport 8445
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiinterface 0.0.0.0
  /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apivariant json

  # Used to enable/disable Tor
  if ! grep -Fq "socksproxytype" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings socksproxytype none
  fi

  if ! grep -Fq "sockshostname" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings sockshostname none
  fi

  if ! grep -Fq "onionservicesonly" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionservicesonly false
  fi

  if ! grep -Fq "onionhostname" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionhostname ""
  fi

  if ! grep -Fq "apiusername" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiusername "bitchan_${APIUSER}"
  fi

  if ! grep -Fq "apipassword" /usr/local/bitmessage/keys.dat; then
      /home/bitchan/env2/bin/crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apipassword "${APIPASS}"
  fi
}

if [ ! -f "/usr/local/bitmessage/knownnodes.dat" ] ; then
  printf "\n+++ knownnodes.dat not present. Copying.\n"
  cp /home/bitchan/install_files/bitmessage/knownnodes.dat /usr/local/bitmessage || return
fi

if [ ! -f "/usr/local/bitmessage/keys.dat" ] ; then
  printf "\n+++ keys.dat not present. Creating and modifying.\n"
  cd /usr/local/bitmessage || return
  /usr/local/bin/pybitmessage -h
  check_keys
else
  printf "\n+++ keys.dat present. checking file for consistency.\n"
  check_keys
fi

chown -R bitchan /usr/local/bitmessage
