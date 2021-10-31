#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
  git checkout 6f9b66ddffa27673b9c9effe299fed6fddd7bb2c  # 2021.03.01
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
