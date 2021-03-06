#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
  git checkout ef849d2dd31167524336575b3e12591149359c70
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
