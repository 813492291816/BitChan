#!/bin/sh

chown -R minode:nobody "$MINODE_HOME"

su - minode

cd /home/minode

if [[ ! -f "/home/minode/minode_data/run_args" ]]; then
  echo "--i2p --i2p-transient --i2p-tunnel-length 3 --i2p-sam-host 172.28.1.6 --host 0.0.0.0 --port 8446" > /home/minode/minode_data/run_args
fi

RUN="python3 -m minode.main $(cat /home/minode/minode_data/run_args)"

echo "$RUN"

exec $RUN
