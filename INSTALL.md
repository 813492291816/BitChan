<h1 align="center">Install BitChan</h1>

- [Install BitChan with Docker](#install-bitchan-with-docker)
- [Install BitChan Without Docker](#install-bitchan-without-docker)

# Install BitChan with Docker

This has been tested to work on [Xubuntu](https://xubuntu.org) 22.04 as a virtual machine in [VirtualBox](https://www.virtualbox.org), and Debian 12 (Bookworm) on a Raspberry Pi 4 and 5, but will likely work on most Debian-based operating systems. Briefly, the following steps are to install Docker and BitChan on a Debian-based operating system.

Follow the instructions at https://docs.docker.com/engine/install/ to install the Docker Engine and the docker-compose plugin, then add your user to the docker group.

```bash
sudo usermod -aG docker $USER
```

Log out and back in for the group change to take effect, then change to the BitChan/docker directory and start the build process.

```bash
git clone https://github.com/813492291816/BitChan
cd BitChan/docker
docker compose up --build -d
```

BitChan can now be accessed at http://172.28.1.1:8000 (If using tor browser, read the README for how to enable access via about:config)

# Install BitChan Without Docker

Installing BitChan with Docker is still the recommended method, however it is possible to install BitChan natively within a Debian-based Linux operating system (outside docker). This has been tested to work on [Xubuntu](https://xubuntu.org) 22.04 as a virtual machine in [VirtualBox](https://www.virtualbox.org), but will likely work on most Debian-based operating systems, as long as you have both Python 2 and Python 3 available.

This currently works but you may find it takes a while for bitmessage to make its initial connections. You can speed up this process by (after following the installation) copying the knownnodes.dat from your existing bitmessage install that has connections to /usr/local/bitchan/bitmessage/ and restarting bitmessage with "sudo service bitchan_bitmessage restart".

Since the addition of the BitTorrentover I2P post attachment upload method, qBittorrent needs to be installed. The safest way to ensure qbittorrent does not leak non-i2p traffic is by using the Docker install method, as this uses iptables within the container to only allow connections to i2pd for torrenting. Use the non-docker install method at your own risk. It is recommended to set qbittorrent behind some type of firewall to only allow it to communicate with i2pd.

## Install general dependencies

```bash
sudo apt update
sudo apt install -yq --no-install-suggests --no-install-recommends git wget
```

## Create directories

```bash
sudo adduser --disabled-password --gecos "" bitchan
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
sudo mkdir -p /usr/local/bitchan_venv2
sudo mkdir -p /usr/local/bitchan_venv3
sudo chmod -R 770 /usr/local/bitchan*
sudo chmod -R 700 /usr/local/bitchan/tor
sudo chmod -R 700 /usr/local/bitchan/tor_data
sudo chown -R bitchan:bitchan /usr/local/bitchan*
```

Log out and back in for the group addition to take effect.

## Clone BitChan

```bash
cd /usr/local/bitchan
git clone https://github.com/813492291816/BitChan
```

## Install & Set Up MySQL

```bash
sudo apt install -yq --no-install-suggests --no-install-recommends mysql-server
sudo mysql
```

At the "mysql>" prompt, enter:

```bash
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'Bitchandbpw';
CREATE DATABASE IF NOT EXISTS bitchan_db;
exit
```

Enter back into the mysql prompt with password "Bitchandbpw":

```bash
mysql -u root -p
```

Enter the following command at the mysql prompt to be able to open the mysql prompt with simply "sudo mysql", and create the BitChan database.

VALIDATE PASSWORD COMPONENT: No
Change the password for root? No
Remove anonymous users? Yes
Disallow root login remotely? Yes
Remove test database and access to it? Yes
Reload privilege tables now? Yes

```bash
#ALTER USER 'root'@'localhost' IDENTIFIED WITH auth_socket;
exit
```

Now run the setup script to disable anonymous login and delete test database.

```bash
sudo mysql_secure_installation
```

After the server has run at least 24 hours or longer, consider running the mysqltuner to assess and recommend a tuning that can improve performance: https://github.com/major/MySQLTuner-perl

## Compile and install tor

If you already have tor installed, skip this step. If you're using non-default tor ports (9050/9051), you'll need to change those in /usr/local/bitchan/BitChan/config (TOR_SOCKS_PORT and TOR_CONTROL_PORT) and /usr/local/bitchan/bitmessage/keys.dat (socksport) to the ports you're using.

If you choose, torsocks will be installed and used to install the rest of BitChan. Wait for tor to be boostrapped 100% before proceeding. You can monitor the progress with "sudo service bitchan_tor status". The first time bootstrapping may take longer than subsequent starts.

```bash
export TORVER="tor-0.4.8.10"
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
sudo chown -R bitchan:bitchan /usr/local/bitchan/tor

sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_tor.service
sudo service bitchan_tor start
```

## Compile and install torsocks

This can be skipped, but you will need to search and remove "torsocks" from any further commands. Torsocks will increase the time it takes to download components, but it will improve privacy by conducting those downloads over tor.

Whether you install torsocks or not, one of the following commands need to be run before proceeding.

If you would like to use torsocks for further connections in the install process, run the next command and proceed with the installation of torsocks.

```bash
export TORSOCKS_RUN="torsocks"
```

Otherwise, to disable torsocks from being used, run this command, and skip the installation of torsocks.

```bash
export TORSOCKS_RUN=""
```

```bash
sudo apt install -yq --no-install-suggests --no-install-recommends autoconf automake libtool gcc

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
sudo ${TORSOCKS_RUN} apt install -yq --no-install-suggests --no-install-recommends \
    python2-minimal python2-dev python-setuptools libssl-dev fakeroot sed \
    build-essential cmake libcap-dev libc-dev crudini

cd ~
${TORSOCKS_RUN} wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue --no-check-certificate https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo ${TORSOCKS_RUN} python2 get-pip.py

# BitChan dependencies
sudo ${TORSOCKS_RUN} apt install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 ffmpeg libsm6 libxext6 \
    nano netbase nginx libcurl4-openssl-dev libjpeg-dev python3-dev python3-pip zlib1g-dev
```

## Set Up Python2 and Python3 virtual environments

```bash
${TORSOCKS_RUN} python2 -m pip install --no-cache-dir virtualenv
python2 -m virtualenv /usr/local/bitchan_venv2
${TORSOCKS_RUN} /usr/local/bitchan_venv2/bin/pip install --no-cache-dir --upgrade pip
${TORSOCKS_RUN} /usr/local/bitchan_venv2/bin/pip install --no-cache-dir -r /usr/local/bitchan/BitChan/requirements_bitmessage.txt

${TORSOCKS_RUN} python3 -m pip install --no-cache-dir virtualenv
python3 -m virtualenv /usr/local/bitchan_venv3
${TORSOCKS_RUN} /usr/local/bitchan_venv3/bin/pip install --no-cache-dir --upgrade pip
${TORSOCKS_RUN} /usr/local/bitchan_venv3/bin/pip install --no-cache-dir -r /usr/local/bitchan/BitChan/requirements.txt
```

## Set Up PyBitmessage

```bash
cd ~
${TORSOCKS_RUN} git clone https://github.com/Bitmessage/PyBitmessage
cd PyBitmessage
git checkout 3d19c3f23fad2c7a26e8606cd95c6b3df417cfbc
${TORSOCKS_RUN} /usr/local/bitchan_venv2/bin/pip install --no-cache-dir -r requirements.txt
sudo ${TORSOCKS_RUN} /usr/local/bitchan_venv2/bin/python2 setup.py install
sudo ln -sf /usr/local/bitchan_venv2/bin/pybitmessage /usr/local/bin/pybitmessage

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

sudo cp /usr/local/bitchan/BitChan/install_files/bitmessage/knownnodes.dat /usr/local/bitchan/bitmessage/
sudo chown -R bitchan.bitchan /usr/local/bitchan/bitmessage
```

## Set Up nginx

```bash
sudo cp /usr/local/bitchan/BitChan/install_files/nginx/nginx.conf /etc/nginx/
sudo cp /usr/local/bitchan/BitChan/install_files/nginx/project.conf /etc/nginx/conf.d/
sudo service nginx restart
```

## Compile and install i2pd

```bash
export I2PVER="2.51.0"
export I2PLOC="https://github.com/PurpleI2P/i2pd/archive/refs/tags/${I2PVER}.tar.gz"

sudo ${TORSOCKS_RUN} apt install -yq --no-install-suggests --no-install-recommends \
    build-essential cmake debhelper libboost-date-time-dev libboost-filesystem-dev libboost-program-options-dev libboost-system-dev libssl-dev zlib1g-dev wget

cd ~
${TORSOCKS_RUN} wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue ${I2PLOC}
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
sudo chown -R bitchan:bitchan /usr/local/bitchan/i2pd/i2pd.conf

sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_i2pd.service
sudo service bitchan_i2pd start
# You should now be able to access the i2pd webconsole at http://127.0.0.1:7070 using user bitchani2p and password bci2ppass
```

If you're setting up a kiosk and want to use an eepsite to access BitChan over HTTP, copy /usr/local/bitchan/BitChan/install_files/i2pd/bitchan_tunnels.conf to /usr/local/bitchan/i2pd/tunnels.conf.d/ and restart i2pd. If you have a key.dat, you can replace bitchan-tunnel.dat in bitchan_tunnels.conf in order to specify your i2p address, otherwise one will be randomly generated.

## Compile and install qBittorrent

Note: torsocks has been removed from the git clone commands due to connection refusals for the submodule downloads.

```bash
sudo ${TORSOCKS_RUN} apt install -yq --no-install-suggests --no-install-recommends \
    autoconf automake build-essential cmake curl git libboost-tools-dev libboost-dev libboost-system-dev libexecs-dev \
    libicu-dev libqt5svg5-dev libssl-dev libtool linux-headers-generic perl pkgconf python3 python3-dev qtbase5-dev \
    qttools5-dev qttools5-dev-tools re2c ninja-build tar zlib1g-dev

cd ~

# Commit 74bc93a37a5e31c78f0aa02037a68fb9ac5deb41 v2.0.10
git clone --shallow-submodules --recurse-submodules https://github.com/arvidn/libtorrent.git ./libtorrent
cd ./libtorrent
git checkout 74bc93a37a5e31c78f0aa02037a68fb9ac5deb41
cmake -Wno-dev -G Ninja -B build -D CMAKE_BUILD_TYPE="Release" -D CMAKE_CXX_STANDARD=17
cmake --build build
sudo cmake --install build
cd ..
rm -rf ./libtorrent

# Commit 785320e7f6a5e228caf817b01dca69da0b83a012 v4.6.4
git clone --shallow-submodules --recurse-submodules https://github.com/qbittorrent/qBittorrent.git ./qbittorrent
cd ./qbittorrent
git checkout 785320e7f6a5e228caf817b01dca69da0b83a012
cmake -Wno-dev -G Ninja -B build -D GUI=OFF -D CMAKE_BUILD_TYPE="release" -D CMAKE_CXX_STANDARD=17
cmake --build build
sudo cmake --install build
cd ..
rm -rf ./qbittorrent

sudo adduser --disabled-password --gecos "" --home /usr/local/bitchan/BitChan/i2p_qb qb
sudo usermod -aG bitchan qb
sudo usermod -aG qb $USER

sudo mkdir -p /usr/local/bitchan/BitChan/i2p_qb/.config
sudo mkdir -p /usr/local/bitchan/BitChan/i2p_qb/.config/qBittorrent
sudo mkdir -p /usr/local/bitchan/BitChan/i2p_qb/Downloads
sudo mkdir -p /usr/local/bitchan/BitChan/i2p_qb/Downloads/temp

# Copy qbittorrent config files
sudo cp /usr/local/bitchan/BitChan/install_files/qbittorrent/qBittorrent.conf /usr/local/bitchan/BitChan/i2p_qb/.config/qBittorrent/
sudo cp /usr/local/bitchan/BitChan/install_files/qbittorrent/watched_folders.json /usr/local/bitchan/BitChan/i2p_qb/.config/qBittorrent/

sudo chown -R qb:qb /usr/local/bitchan/BitChan/i2p_qb
sudo chmod -R 770 /usr/local/bitchan/BitChan/i2p_qb

# Set up persistent iptables rules to prevent user qb that runs qbittorrent from accessing the internet but allow connecting locally to i2pd
sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean false"
sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean false"
sudo ${TORSOCKS_RUN} apt install -y iptables-persistent
sudo cp /usr/local/bitchan/BitChan/install_files/qbittorrent/rules.v4 /etc/iptables/
sudo chown root:root /etc/iptables/rules.v4
sudo chmod 644 /etc/iptables/rules.v4
sudo systemctl enable --now netfilter-persistent.service
sudo service iptables restart

sudo systemctl enable /usr/local/bitchan/BitChan/install_files/bitchan_qbittorrent.service
sudo service bitchan_qbittorrent start
# You should now be able to access the qbittorrent Web UI at http://127.0.0.1:8080
```

You can verify no connections are leaking from the qb user that runs qbittorrent.

```bash
# Verify that your current user has internet
ping yahoo.com
# Verify that the internet is not accessible by use qb (the user that will run qbittorrent)
sudo su qb -c "ping yahoo.com"
# You should see the following returned:
### ping: yahoo.com: Temporary failure in name resolution
# qbittorrent can now be used with i2p without the possibility of connections leaking to the clearnet
```

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

BitChan can now be accessed at http://127.0.0.1:8000 (If using tor browser, read the README for how to enable localhost access via about:config)

# Notes

## Initial connection to bitmessage network

The default connection settings for bitmessage allows incoming connections to use tor and clearnet and outgoing connections to use tor. You can check the number of bitmessage connections that have been made (named networkConnections) under Bitmessage Status on the Status page. If you don't have at least one connection after an hour, try changing the Incoming and Outgoing Connections setting on the Configuration page.

## Upgrading No-Docker Install

```bash
cd /usr/local/bitchan/BitChan
git pull
sudo systemctl daemon-reload
sudo service bitchan_qbittorrent restart
sudo service bitchan_backend restart
sudo service bitchan_frontend restart
```

Upgrading tor and i2pd will need to be done manually, by repeating the compilation steps for each, with the new version.
