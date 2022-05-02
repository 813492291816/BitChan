#!/bin/bash

APIPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)

mkdir -p /usr/local/bitmessage
mkdir -p /usr/local/tor/bm
mkdir -p /usr/local/tor/cus
mkdir -p /usr/local/tor/rand
chmod -R 700 /usr/local/tor

check_keys() {
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings socksproxytype SOCKS5
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings sockshostname bitchan_tor
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings socksport 9060
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionport 8444
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings sockslisten true
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionbindip 172.28.1.3
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings extport 8444
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apienabled true
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiport 8445
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiinterface 0.0.0.0
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apivariant json
  crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apiusername bitchan

  if ! grep -Fq "onionservicesonly" /usr/local/bitmessage/keys.dat; then
      crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionservicesonly false
  fi

  if ! grep -Fq "onionhostname" /usr/local/bitmessage/keys.dat; then
      crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings onionhostname ""
  fi

  if ! grep -Fq "apipassword" /usr/local/bitmessage/keys.dat; then
      crudini --set /usr/local/bitmessage/keys.dat bitmessagesettings apipassword "${APIPASS}"
  fi
}

if [ ! -f "/usr/local/bitmessage/keys.dat" ] ; then
  printf "\n+++ keys.dat not present. Creating and modifying.\n"
  cd /usr/local/bitmessage || return
  /usr/local/bin/pybitmessage -h
  check_keys
else
  printf "\n+++ keys.dat present. checking file for consistency.\n"
  check_keys
fi
