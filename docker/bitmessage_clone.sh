#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
#  git checkout 6f9b66ddffa27673b9c9effe299fed6fddd7bb2c  # 2021.03.01
#  git checkout 113808a60c6ab41b4bef14463746d20a2a754f48  # 2021.11.02
  git checkout 9c872ef676cafdebf07244a9dbd6e00a29154bef  # 2022.01.18
#  git checkout a67572d70854fd59a3baffbe286a9d77a90e43d7  # 2022.04.25 not working
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
