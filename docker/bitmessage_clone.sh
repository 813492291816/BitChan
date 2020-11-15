#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
  git checkout 93bf7ad62c252df85f3ff2bcac8f3fc40dbf33e9
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
