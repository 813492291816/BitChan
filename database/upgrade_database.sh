#!/bin/bash

if [ ! -f "/usr/local/bitchan/bitchan.db" ] ; then
  printf "\n[%s] +++ /usr/local/bitchan/bitchan.db not present. Not running alembic upgrade.\n" "$(date)" | tee -a /usr/local/bitchan/log/alembic.log
else
  printf "\n[%s] +++ /usr/local/bitchan/bitchan.db present. Running alembic upgrade.\n" "$(date)" | tee -a /usr/local/bitchan/log/alembic.log
  cd /usr/local/bitchan/BitChan/database || return
  /usr/local/bitchan/venv3/bin/alembic upgrade head | tee -a /usr/local/bitchan/log/alembic.log
  /usr/local/bitchan/venv3/bin/python /usr/local/bitchan/BitChan/database/upgrade_database_post.py | tee -a /usr/local/bitchan/log/alembic.log
fi
