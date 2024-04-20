#!/bin/bash

printf "\n+++ Running alembic upgrade.\n"
cd /home/bitchan/database || return
alembic upgrade head
python3 /home/bitchan/database/upgrade_database_post.py
