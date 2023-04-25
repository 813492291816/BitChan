<h1 align="center">Install BitChan</h1>

- [Install BitChan with Docker](#install-bitchan-with-docker)
- [Install BitChan Without Docker](#install-bitchan-without-docker)

# Install BitChan with Docker

This has been tested to work on [Xubuntu](https://xubuntu.org) 22.04 as a virtual machine in [VirtualBox](https://www.virtualbox.org), and Debian Buster on a Raspberry Pi 4, but will likely work on most Debian-based operating systems. Open a terminal and run the following commands. NOTE: These commands are taken from the Ubuntu install section of the Docker website, above. Since these commands can change at any time, it is recommended to use the above link for the most up-to-date install instructions for Docker Engine and the docker-compose plugin.

Briefly, the following steps are to install Docker and BitChan on an Ubuntu-based operating system.

## Install Docker

Follow the instructions at https://docs.docker.com/engine/install/ to install Docker.

## Install BitChan

```bash
git clone https://github.com/813492291816/BitChan
cd BitChan/docker
sudo make daemon
```

# Install BitChan Without Docker

Installing BitChan with Docker is still the recommended method, however it is possible to install BitChan natively within a Debian-based Linux operating system (outside docker). This has been tested to work on [Xubuntu](https://xubuntu.org) 22.04 as a virtual machine in [VirtualBox](https://www.virtualbox.org), but will likely work on most Debian-based operating systems

These are the steps to install BitChan in Linux. This currently works but you may find it takes a while for bitmessage to make its initial connections. You can speed up this process by (after following the installation) copying the knownnodes.dat from your existing bitmessage install that has connections to /usr/local/bitchan/bitmessage/ and restarting bitmessage with "sudo service bitchan_bitmessage restart".

## Install general dependencies

```bash
# General dependencies
sudo apt update
sudo apt install -yq --no-install-suggests --no-install-recommends git wget
```

## Create directories

```bash
sudo useradd bitchan
sudo usermod -aG bitchan $USER
sudo mkdir -p /usr/local/bitchan
sudo mkdir -p /usr/local/bitchan/bitmessage
sudo mkdir -p /usr/local/bitchan/downloaded_files
sudo mkdir -p /usr/local/bitchan/gnupg
sudo mkdir -p /usr/local/bitchan/i2pd
sudo mkdir -p /usr/local/bitchan/i2pd/tunnels.conf.d
sudo mkdir -p /usr/local/bitchan/i2pd_data
sudo mkdir -p /usr/local/bitchan/log
sudo mkdir -p /usr/local/bitchan/tor
sudo mkdir -p /usr/local/bitchan/tor/bm
sudo mkdir -p /usr/local/bitchan/tor/cus
sudo mkdir -p /usr/local/bitchan/tor/rand
sudo mkdir -p /usr/local/bitchan/tor/authorized_clients
sudo mkdir -p /usr/local/bitchan/tor_data
sudo mkdir -p /usr/local/bitchan-env
sudo chmod -R 770 /usr/local/bitchan
sudo chmod -R 700 /usr/local/bitchan/tor
sudo chmod -R 700 /usr/local/bitchan/tor_data
sudo chown -R bitchan.bitchan /usr/local/bitchan
```

Log out and back in for the group addition to take effect.

## Clone BitChan

```bash
cd /usr/local/bitchan
git clone https://github.com/813492291816/BitChan
```

## Install & Setup tor

If you already have tor installed, skip this step. If you're using non-default tor ports (9050/9051), you'll need to change those in /usr/local/bitchan/BitChan/config (TOR_SOCKS_PORT and TOR_CONTROL_PORT) and /usr/local/bitchan/bitmessage/keys.dat (socksport) to the ports you're using.

torsocks will be used following the installation of tor, to install the rest of BitChan.

```bash
export TORVER="tor-0.4.7.9"
export TORLOC="https://www.torproject.org/dist/${TORVER}.tar.gz"
export TORPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)

sudo apt update
sudo apt install -yq --no-install-suggests --no-install-recommends \
    build-essential automake autoconf libevent-dev libssl-dev zlib1g-dev zlib1g liblzma-dev libzstd-dev systemd libsystemd-dev pkg-config libnss3-dev wget

cd ~
wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue ${TORLOC}
tar xvzf ${TORVER}.tar.gz
cd ${TORVER}
./configure --enable-systemd --enable-nss
make
sudo make install
cd ~
rm -rf ${TORVER}.tar.gz
rm -rf ${TORVER}

sudo cp /usr/local/bitchan/BitChan/install_files/tor/torrc /usr/local/bitchan/tor/
echo "${TORPASS}" | sudo dd of=/usr/local/bitchan/tor/torpass
echo "HashedControlPassword $(tor --quiet --hash-password ${TORPASS})" | sudo tee -a /usr/local/bitchan/tor/torrc

sudo chmod -R 700 /usr/local/bitchan/tor
sudo chown -R bitchan.bitchan /usr/local/bitchan/tor

sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_tor.service
sudo service bitchan_tor start
```

## Install torsocks

```bash
sudo apt install -yq --no-install-suggests --no-install-recommends \
    autoconf automake libtool gcc

cd ~
git clone https://git.torproject.org/torsocks.git
cd torsocks
./autogen.sh
./configure
make
sudo make install
cd ~
rm -rf torsocks
```

## Install bitchan and bitmessage dependencies

```bash
# Bitmessage dependencies
sudo torsocks apt install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-setuptools libssl-dev fakeroot sed \
    build-essential cmake libcap-dev libc-dev crudini
cd ~
torsocks wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue --no-check-certificate https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo torsocks python2 get-pip.py

# BitChan dependencies
sudo torsocks apt install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 ffmpeg libsm6 libxext6 \
    nano netbase nginx libcurl4-openssl-dev libjpeg-dev python3-dev python3-pip zlib1g-dev
```

## Setup Python2 and Python3 virtual environments

```bash
torsocks python2 -m pip install virtualenv
python2 -m virtualenv /usr/local/bitchan/venv2
torsocks /usr/local/bitchan/venv2/bin/pip install --upgrade pip
torsocks /usr/local/bitchan/venv2/bin/pip install -r /usr/local/bitchan/BitChan/requirements_bitmessage.txt

torsocks python3 -m pip install virtualenv
python3 -m virtualenv /usr/local/bitchan/venv3
torsocks /usr/local/bitchan/venv3/bin/pip install --upgrade pip
torsocks /usr/local/bitchan/venv3/bin/pip install -r /usr/local/bitchan/BitChan/requirements.txt
```

## Setup PyBitmessage

```bash
cd ~
torsocks git clone https://github.com/Bitmessage/PyBitmessage
cd PyBitmessage
git checkout 3d19c3f23fad2c7a26e8606cd95c6b3df417cfbc
torsocks /usr/local/bitchan/venv2/bin/pip install -r requirements.txt
sudo torsocks /usr/local/bitchan/venv2/bin/python2 setup.py install
sudo ln -sf /usr/local/bitchan/venv2/bin/pybitmessage /usr/local/bin/pybitmessage

export BITMESSAGE_HOME="/usr/local/bitchan/bitmessage"
cd /usr/local/bitchan/bitmessage
/usr/local/bin/pybitmessage -h

export APIUSER=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c12 && echo)
export APIPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings socksproxytype SOCKS5
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings sockshostname 127.0.0.1
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings socksport 9050
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings onionport 8444
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings sockslisten False
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings onionbindip 127.0.0.1
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings extport 8444
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apienabled True
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apiport 8445
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apiinterface 127.0.0.1
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apivariant json
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings onionservicesonly False
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings onionhostname ""
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apiusername "bitchan_${APIUSER}"
sudo crudini --set /usr/local/bitchan/bitmessage/keys.dat bitmessagesettings apipassword "${APIPASS}"
sudo cp /usr/local/bitchan/BitChan/install_files/knownnodes.dat /usr/local/bitchan/bitmessage/
sudo chown -R bitchan.bitchan /usr/local/bitchan/bitmessage
```

## Setup nginx

```bash
sudo cp /usr/local/bitchan/BitChan/install_files/nginx/nginx.conf /etc/nginx/
sudo cp /usr/local/bitchan/BitChan/install_files/nginx/project.conf /etc/nginx/conf.d/
sudo service nginx restart
```

## Install i2pd

```bash
export I2PVER="2.47.0"
export I2PLOC="https://github.com/PurpleI2P/i2pd/archive/refs/tags/${I2PVER}.tar.gz"

sudo torsocks apt install -yq --no-install-suggests --no-install-recommends \
    build-essential debhelper libboost-date-time-dev libboost-filesystem-dev libboost-program-options-dev libboost-system-dev libssl-dev zlib1g-dev wget

cd ~
torsocks wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue ${I2PLOC}
mkdir i2pd
tar xzf ${I2PVER}.tar.gz -C i2pd --strip-components=1
cd i2pd/build
cmake -DWITH_HARDENING=ON -DWITH_ADDRSANITIZER=ON
make
sudo make install
cd ../..
rm -rf ${I2PVER}.tar.gz
rm -rf i2pd

sudo cp /usr/local/bitchan/BitChan/install_files/i2pd/i2pd.conf /usr/local/bitchan/i2pd/i2pd.conf

sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_i2pd.service
sudo service bitchan_i2pd start
```

If you're setting up a kiosk and want to use an eepsite to access BitChan over HTTP, copy /usr/local/bitchan/BitChan/install_files/i2pd/bitchan_tunnels.conf to /usr/local/bitchan/i2pd/tunnels.conf.d/ and restart i2pd. If you have a key.dat, you can replace bitchan-tunnel.dat in bitchan_tunnels.conf in order to specify your i2p address, otherwise one will be randomly generated.

## Enable services

```bash
sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_bitmessage.service
sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_frontend.service
sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_backend.service
```

## Start BitChan Frontend

```bash
sudo service bitchan_frontend start
curl -sL -I 127.0.0.1:8000/favicon.ico > /dev/null
```

Connecting to 127.0.0.1:8000/favicon.ico (above) creates the database and is required to be done only once, before starting the backend for the first time.

## Start BitChan Backend

```bash
sudo service bitchan_backend start
```

BitChan can now be accessed at http://127.0.0.1:8000

# Notes

## Initial connection to bitmessage network

The default connection settings for bitmessage allows incoming connections to use tor and clearnet and outgoing connections to use tor. You can check the number of bitmessage connections that have been made (named networkConnections) under Bitmessage Status on the Status page. If you don't have at least one connection after an hour, try changing the Incoming and Outgoing Connections setting on the Configuration page.

## Upgrading No-Docker Install

```bash
cd /usr/local/bitchan/BitChan
git pull
sudo systemctl daemon-reload
sudo service bitchan_backend restart
sudo service bitchan_frontend restart
```
