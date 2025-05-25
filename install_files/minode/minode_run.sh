#!/bin/sh

cd /usr/local/bitchan/minode

if [[ ! -f "/usr/local/bitchan/minode/minode_data/run_args" ]]; then
  echo "--i2p --i2p-transient --i2p-tunnel-length 3 --i2p-sam-host 127.0.0.1 --host 0.0.0.0 --port 8446" > /usr/local/bitchan/minode/minode_data/run_args
fi

RUN="/usr/local/bitchan_venv3/bin/python -m minode.main $(cat /usr/local/bitchan/minode/minode_data/run_args)"

echo "$RUN"

exec $RUN
