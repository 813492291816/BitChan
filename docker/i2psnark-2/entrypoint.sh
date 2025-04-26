#!/bin/sh

CGID=$(getent group i2psnark | cut -d: -f3)
CUID=$(id -u i2psnark)

if [[ "$HOST_GID" != "" && "$CGID" != "$HOST_GID" ]]; then
  groupmod -g "$HOST_GID" i2psnark
else
  HOST_GID=$CGID
fi

if [[ "$HOST_UID" != "" && "$CUID" != "$HOST_UID" ]]; then
  usermod -u "$HOST_UID" -g "$HOST_GID" i2psnark
fi

if [[ "$I2CP_HOST" == "" ]]; then
  echo "I2CP host is empty. Please, setup value in the Docker Environment."
  exit 1
fi

if [[ "$I2CP_PORT" == "" ]]; then
  echo "I2CP port is empty. Please, setup value in the Docker Environment."
  exit 2
fi

if [[ ! -f "/i2psnark/i2psnark.config.d/i2psnark.config" ]]; then
  cp -f /i2psnark/i2psnark.config.default /i2psnark/i2psnark.config.d/i2psnark.config
fi

# Ensure user rights
chown i2psnark:"$HOST_GID" /i2psnark
chown -R i2psnark:"$HOST_GID" /i2psnark/i2psnark.config.d
chown i2psnark:"$HOST_GID" /i2psnark/downloads

sed -i "s/^i2psnark.allowedHosts=.*$/i2psnark.allowedHosts=${HOSTNAMES}/g" /i2psnark/i2psnark-appctx.config
sed -i "s/^i2psnark.i2cpHost=.*$/i2psnark.i2cpHost=${I2CP_HOST}/g" /i2psnark/i2psnark.config.d/i2psnark.config
sed -i "s/^i2psnark.i2cpPort=.*$/i2psnark.i2cpPort=${I2CP_PORT}/g" /i2psnark/i2psnark.config.d/i2psnark.config

cd /i2psnark
exec su-exec i2psnark:"$HOST_GID" java -jar i2psnark.jar
