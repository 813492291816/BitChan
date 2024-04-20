#!/bin/bash

if [ ! -d "/home/bitchan/PyBitmessage" ] ; then
  printf "\n+++ PyBitmessage directory not found. Cloning.\n"
  git clone https://github.com/Bitmessage/PyBitmessage /home/bitchan/PyBitmessage
  cd /home/bitchan/PyBitmessage || return
#  git checkout 6f9b66ddffa27673b9c9effe299fed6fddd7bb2c  # 2021.03.01
#  git checkout 113808a60c6ab41b4bef14463746d20a2a754f48  # 2021.11.02
#  git checkout 9c872ef676cafdebf07244a9dbd6e00a29154bef  # 2022.01.18
#  git checkout a67572d70854fd59a3baffbe286a9d77a90e43d7  # 2022.04.25 not working
#  git checkout e6ecaa5e7d7bedfe9f7271fa390f3d3c6691d51c  # 2022.11.06 new API endpoint, API client doesn't work!
  git checkout 3d19c3f23fad2c7a26e8606cd95c6b3df417cfbc   # 2023.01.13
else
  printf "\n+++ PyBitmessage directory already present. Skipping.\n"
fi
