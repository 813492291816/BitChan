#!/bin/sh

if [ $HOST_USER_ID -le 499 ] || [ $HOST_GROUP_ID -eq 0 ]; then
  echo "Do not use root or system ids as HOST_USER_ID and HOST_GROUP_ID! Exiting..."
  exit
fi

# Block qbittorrent from making outbound connections
# Allows it to only connect to i2pd for torrenting over i2p
ufw enable
ufw default allow incoming
ufw default deny outgoing
ufw allow out to 172.28.1.6/32  # i2pd IP

mkdir -p "$QB_HOME"/.config
mkdir -p "$QB_HOME"/.config/qBittorrent
mkdir -p "$QB_HOME"/Downloads
mkdir -p "$QB_HOME"/Downloads/temp
mv /qBittorrent.conf "$QB_HOME"/.config/qBittorrent/
chmod -R 777 "$QB_HOME"
addgroup -g $HOST_GROUP_ID qb 2> /dev/null
groupmod -g $HOST_GROUP_ID $(cat /etc/group | grep qb: | cut -d: -f1) 2> /dev/null
adduser -D -s /bin/sh -u $HOST_USER_ID -G $(cat /etc/group | grep x:$HOST_GROUP_ID: | cut -d: -f1) -h "$QB_HOME" qb 2> /dev/null
usermod -o -u $HOST_USER_ID -g $(cat /etc/group | grep x:$HOST_GROUP_ID: | cut -d: -f1) -d "$QB_HOME" -m qb 2> /dev/null
addgroup qb $(cat /etc/group | grep x:$HOST_GROUP_ID: | cut -d: -f1) 2> /dev/null
chown -R qb:$(cat /etc/group | grep x:$HOST_GROUP_ID: | cut -d: -f1) "$QB_HOME"
su - qb -c "echo 'umask 0000' > ~/.profile"
sleep 10
su - qb -c "qbittorrent-nox"
exit
