#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
  git checkout 9265235053aad4261bf8c2da4809acc3d3fb69f1
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
