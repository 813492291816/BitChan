#!/bin/bash

if [ ! -f "/usr/local/bitchan/bitchan.db" ] ; then
  printf "\n+++ /usr/local/bitchan/bitchan.db not present. Not running alembic upgrade.\n"
else
  printf "\n+++ /usr/local/bitchan/bitchan.db present. Running alembic upgrade.\n"
  cd /home/bitchan/database || return
  alembic upgrade head
  python3 /home/bitchan/database/upgrade_database_post.py
fi
