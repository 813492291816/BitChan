#!/bin/bash

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd -P )

if [[ "$EUID" -ne 0 ]]; then
  printf "Execute script as root.\n"
  exit 1
fi

# Install general dependencies
printf "\n+++ Install general dependencies"
apt install -y libssl-dev openssl python2 gawk g++

LIBQT4_VERSION=$(apt-cache policy libqtassistantclient4 | grep 'Installed' | gawk '{print $2}')
PYQT4_VERSION=$(apt-cache policy python-qt4 | grep 'Installed' | gawk '{print $2}')
if [[ "${LIBQT4_VERSION}" != "4.6.3-7build1" ]] || [[ "${PYQT4_VERSION}" != "4.12.1+dfsg-2" ]]; then
  add-apt-repository ppa:rock-core/qt4 -y  # Add Qt4 repository
fi

# Install libqtassistantclient4
if [[ "${LIBQT4_VERSION}" != "4.6.3-7build1" ]]; then
  printf "\n+++ libqtassistantclient4 not found. Installing."
  wget archive.ubuntu.com/ubuntu/pool/universe/q/qt-assistant-compat/libqtassistantclient4_4.6.3-7build1_amd64.deb
  apt install -y ./libqtassistantclient4_4.6.3-7build1_amd64.deb
else
  printf "\n+++ Correct version of libqtassistantclient4 found.\n"
fi

# Install python-qt4
if [[ "${PYQT4_VERSION}" != "4.12.1+dfsg-2" ]]; then
  printf "\n+++ python-qt4 not found. Installing."
  wget archive.ubuntu.com/ubuntu/pool/universe/p/python-qt4/python-qt4_4.12.1+dfsg-2_amd64.deb
  apt install -y ./python-qt4_4.12.1+dfsg-2_amd64.deb
else
  printf "\n+++ Correct version of python-qt4 found.\n"
fi

# Download/install PyBitmessage
cd "${DIR}" || return
if [ ! -f "/usr/local/bin/pybitmessage" ] ; then
  printf "\n+++ Clone PyBitmessage..."
  if ! git clone https://github.com/Bitmessage/PyBitmessage ; then
    printf " Couldn't clone PyBitmessage.\n"
  else
    cd "${DIR}/PyBitmessage" || return
    python2 setup.py install
  fi
else
  printf "\n+++ PyBitmessage already installed.\n"
fi
