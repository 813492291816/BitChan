#!/bin/bash

printf "\n+++ Running alembic upgrade.\n"
cd /home/bitchan/database || return
/home/bitchan/env3/bin/alembic upgrade head
/home/bitchan/env3/bin/python3 /home/bitchan/database/upgrade_database_post.py
