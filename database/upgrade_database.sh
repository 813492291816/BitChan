#!/bin/bash

UP=$(pgrep mysql | wc -l);

if [ "$UP" -ne 1 ]; then
  printf "\n[%s] +++ MySQL not running. Not running alembic upgrade.\n" "$(date)" | tee -a /usr/local/bitchan/log/alembic.log
else
  printf "\n[%s] +++ MySQL running. Running alembic upgrade.\n" "$(date)" | tee -a /usr/local/bitchan/log/alembic.log
  cd /usr/local/bitchan/BitChan/database || return
  /usr/local/bitchan_venv3/bin/alembic upgrade head | tee -a /usr/local/bitchan/log/alembic.log
  /usr/local/bitchan_venv3/bin/python /usr/local/bitchan/BitChan/database/upgrade_database_post.py | tee -a /usr/local/bitchan/log/alembic.log
fi
