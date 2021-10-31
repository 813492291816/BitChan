=======
BitChan
=======

Version: 1.0.0

BitChan is a decentralized anonymous imageboard inspired by `BitBoard <https://github.com/michrob/bitboard>`__ and built on top of `Bitmessage <https://bitmessage.org>`__ with `Tor <https://www.torproject.org>`__ and `GnuPG <https://gnupg.org>`__.

Try it out at http://bitchanr4b64govofzjthtu6qc4ytrbuwbgynapkjileajpycioikxad.onion (an anonymous donor has paid for a BitChan instance to be set up on a VPS in `Kiosk Mode <https://github.com/813492291816/BitChan/blob/master/MANUAL.md#kiosk-mode>`__). This is only accessible with `Tor Browser <https://www.torproject.org>`__.


BitChan solves a number of security and free speech problems that have plagued most imageboards. Centralized imageboards can be taken offline or hijacked and can leak user data. BitChan reduces the likelihood of this by being decentralized, requiring all connections to go through Tor, and not requiring JavaScript.

When installed locally on your computer, BitChan acts as an extension to Bitmessage, a decentralized, blockchain-based messaging program. Bitmessage relies on public key encryption similar to PGP and decentralized message delivery, which due to the fact that every message is distributed to every client, also provides plausible deniability (i.e. no one knows who the message was intended to go to). Bitmessage handles the sending and receiving of messages and BitChan acts as a sophisticated message processor, which includes a web front end. All communication happens over the Tor onion routing network for anonymity and every BitChan message is encrypted using GPG, an open source version of PGP (Pretty Good Privacy). Instead of connecting to a stranger's server and volunteering potentially identifying information, BitChan anonymously adds your message to the Bitmessage block. Everyone on the Bitmessage network downloads and shares your encrypted messages and only those with the correct credentials can decrypt them.

Users of centralized forums often have to deal with overzealous moderators and sometimes even pressure from State powers that tend to suffocate the forum's culture. BitChan's moderation is multifaceted, but to be brief, the option exists to create entirely unmoderatable boards. Due to its decentralized design, BitChan cannot be moderated by its developers or the government. Indeed, there is no way to disconnect BitChan from the internet, and as long as people are still running Bitmessage, BitChan lives completely untouchable by any authority. With that said, boards can be created with a variety of rules which allow board owners or admins to moderate them if so desired. Unmoderated boards can be locally moderated by the user. Additionally, users can set their install to act as a Kiosk and enable a Tor Hidden Onion service to allow anonymous users to utilize their install through an .onion address, however when accessing BitChan in this way, you will be constrained by the settings that user sets for their BitChan install. In order to utilize the full features of BitChan, including reliability and a censor-free environment, you will need to install it locally on your computer.

BitChan offers boards for a forum-like experience with image and file sharing, lists to organize and share other boards and lists, along with a host of additional features to enhance posts and provide board and list management with the use of owner, admin, and user permissions. Boards and lists can be public or private, with or without owners or admins, allowing a full range from completely unmoderatable to strictly allowing only select addresses to post or modify list contents.

Quick Links: `Manual <MANUAL.md>`__, `Changelog <CHANGELOG.md>`__, `Screenshots <SCREENSHOTS.md>`__

--------------

.. contents::
   :depth: 4
..

Screenshots
===========

See `Screenshots <SCREENSHOTS.md>`__

Features
========

- Security

  - All essential features work with JavaScript completely disabled
  - All internet traffic (Bitmessage/uploads/downloads) through tor with fake UserAgent
  - All messages PGP-encrypted with user-selectable cipher and key length
  - Encryption, fragmentation, and hashing to secure and verify authenticity of received post attachment files
  - Bitmessage Identities for private addresses that only you control

- Boards for posting messages and Lists for sharing other boards and lists

  - Permissions for board/list ownership and administration
  - Public access where anyone can post on a board or add to a list
  - Private access where only select addresses can post or modify a list
  - Several user permissions (Owners, Admins, Users, and Restricted)
  - Rules to allow board/list Owners to determine if certain features are enabled
  - Owner options to set long description, banner and spoiler images, word replacements, custom CSS
  - Address Book to saved addresses and labels will appear next to those addresses
  - Post popup previews
  - Overboard, catalogs and recent pages
  - Mod log to track moderation and other changes
  - Sticky/pin/anchor functions for threads

- Board Features

  - Post with any Bitmessage address you can send from
  - Threaded posting with text enhancements
  - Embed images/videos in posts
  - Images and videos in posts expand to full-width on click
  - Search

  - File Attachments

    - Can have any file type attached
    - Send through Bitmessage (if file small enough, <= ~250 KB)
    - Support for external upload site (Anonfiles, Bayfiles, Forumfiles, Uplovd)
    - Support for post text replacements: dice (#3D20), cards (#C5), flip (#flip), 8ball (#8ball), tarot card (#t5), Crowley tarot (#ct5), random book quote (#stich)
    - Support for post text styles: @@bold@@, \~\~italic\~\~, \_\_underline\_\_, ++strikethrough++, ==big==, \*\*spoiler\*\*, ^s shadow ^s, [meme]meme[/meme], [autism]autism[/autism], [flash]flash[/flash], [aa]ascii art[/aa], and more

- Owner/Admin Commands

  - Owners can set a custom CSS, word replacements, and banner image
  - Board Owners/Admins can delete threads and posts (affects all users of a board)
  - Board Owners/Admins can ban users from posting (affects all users of a board)
  - Users can block address from posting to one or all boards (only local effects)

- Mailbox system for messaging other Bitmessage addresses

  - Read, delete, reply, and forward messages
  - Message composition page to send messages
  - Send a message directly from a board to a post's address

- Kiosk mode
  - Allows you to publicly host you BitChan instance in a secure manner
  - Host a .onion hidden service to access BitChan instance from the web
  - Options to keep your kiosk completely private for only your use or allow the public to view or post
  - Permission and/or login system to secure and control access to your BitChan Instance

- Database
  - Upgrade system to automatically upgrade BitChan database to new schemas
  - Export and import your database

Setup
=====

BitChan is distributed with a stable version of Bitmessage and runs inside several docker containers that's orchestrated by docker-compose. This allows cross-platform compatibility and isolation of your install from your operating system. For a consistent install environment, installing BitChan within a virtual machine running Xubuntu 20.04 is described below, however you can install BitChan in any operating system of your choice.

Install BitChan
---------------

To install BitChan, first install `docker <https://docs.docker.com/get-docker/>`__ and `docker-compose <https://docs.docker.com/compose/install/>`__, then change to the BitChan/docker directory and execute:

.. code::

    docker-compose up --build -d


If you get a timeout error while downloading any of the docker image files, just run the command again until it successfully finishes all downloads.

Install on Debian-Based Operating Systems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following steps are to install BitChan on a Debian-based operating system. This has been tested on `Xubuntu <https://xubuntu.org>`__ 20.04 and 21.04 as virtual machines in `VirtualBox <https://www.virtualbox.org/>`__, and Debian Buster (ARM). Open a terminal and run the following commands:

.. code::

    sudo apt install build-essential docker.io docker-compose git
    sudo systemctl enable docker
    git clone https://github.com/813492291816/BitChan
    cd BitChan/docker
    sudo make daemon


Post-install
~~~~~~~~~~~~

BitChan will automatically start at boot (if enabled) and runs on port 8000 by default, which can be accessed by visiting http://localhost:8000 or http://172.28.1.1:8000 in a web browser.

For added security, it's recommended to either A) use tor browser or B) configure another browser to connect through tor.

- A: Tor Browser: Install tor browser (``sudo apt install torbrowser-launcher``). Launch tor browser and enter ``about:config`` in the address bar. Search for ``network.proxy.no_proxies_on`` and enter ``172.28.1.1`` to exclude the BitChan IP address from the proxy. Open BitChan at ``http://172.28.1.1:8000``.

- B: Configure your browser to use the Tor SOCKS5 proxy with the host ``172.28.1.2`` and port 9060 (the IP and port for tor running in the tor docker container). Open BitChan at ``http://localhost:8000``.

Verify your browser is using tor by visiting `https://check.torproject.org <https://check.torproject.org>`__.

Build BitChan Outside Docker
----------------------------

These are the general steps to install and set up tor, nginx, PyBitmessage, and BitChan outside docker. If you want to build BitChan outside of docker, YMMV getting everything to play nicely together. Using Docker is still the preferred method.

Create directories for user data

```bash
sudo mkdir -p /usr/local/bitmessage
sudo mkdir -p /usr/local/bitchan
sudo mkdir -p /usr/local/bitchan/log
sudo mkdir -p /usr/local/bitchan/downloaded_files
chown -R user.user /usr/local/bitmessage
chown -R user.user /usr/local/bitchan
```

Install apt dependencies

```bash
sudo apt-get update
sudo apt-get install -yq --no-install-suggests --no-install-recommends curl secure-delete \\
    gnupg2 build-essential ffmpeg libsm6 libxext6 docker.io python3-dev python3-opencv \\
    python3-setuptools python3-distutils python3-pip netbase libjpeg-dev zlib1g-dev \\
    python-msgpack dh-python python-all-dev build-essential libssl-dev python-stdeb \\
    fakeroot python-pip libcap-dev nano sed git nginx tor
```

Create Python2 and Python3 virtual environments

```bash
virtualenv -p python2 /home/user/venv2
virtualenv -p python3 /home/user/venv3
```

Clone PyBitmessage and install pip2 dependencies

```bash
cd /home/user
git clone https://github.com/Bitmessage/PyBitmessage
cd PyBitmessage
/home/user/venv2/bin/pip install -r requirements.txt
sudo /home/user/venv2/bin/python2 setup.py install
```

Setup PyBitmessage keys.dat

```bash
export BITMESSAGE_HOME="/usr/local/bitmessage"
/usr/local/bin/pybitmessage -h
sed -i '/apivariant/d' /usr/local/bitmessage/keys.dat \\
    && sed -i 's/socksproxytype.*/socksproxytype = SOCKS5/' /usr/local/bitmessage/keys.dat \\
    && sed -i 's/sockshostname.*/sockshostname = localhost/' /usr/local/bitmessage/keys.dat \\
    && sed -i 's/socksport.*/socksport = 9050/' /usr/local/bitmessage/keys.dat \\
    && echo "apienabled = true" >> /usr/local/bitmessage/keys.dat \\
    && echo "apiport = 8445" >> /usr/local/bitmessage/keys.dat \\
    && echo "apiinterface = 0.0.0.0" >> /usr/local/bitmessage/keys.dat \\
    && echo "apiusername = bitchan" >> /usr/local/bitmessage/keys.dat \\
    && echo "apipassword = $(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)" >> /usr/local/bitmessage/keys.dat
```

Clone BitChan and install pip3 dependencies

```bash
cd /home/user
git clone https://github.com/813492291816/BitChan
cd BitChan
/home/user/venv3/bin/pip install -r requirements.txt
```

edit /home/user/BitChan/config.py and change BM_HOST and TOR_HOST to "localhost"

Setup nginx

```bash
sudo rm /etc/nginx/nginx.conf
sudo cp /home/user/BitChan/docker/nginx/nginx.conf /etc/nginx/
sudo rm /etc/nginx/conf.d/default.conf
sudo cp /home/user/BitChan/docker/nginx/project.conf /etc/nginx/conf.d/
sudo service nginx restart
```

Setup tor

```bash
sudo echo "HashedControlPassword $(tor --quiet --hash-password torpass1234)" >> /etc/tor/torrc
sudo service tor restart
```

Start Bitmessage

```bash
export BITMESSAGE_HOME="/usr/local/bitmessage"
/usr/local/bin/pybitmessage -d
```

Start BitChan Backend

```bash
/home/user/venv3/python /home/user/BitChan/bitchan_daemon.py
```

Start BitChan Frontend

```bash
cd /home/user/BitChan
/home/user/venv3/gunicorn --workers 1 --threads 4 --timeout 1800 --bind unix:/usr/local/bitchan/bitchan.sock bitchan_flask:app
```

Open http://127.0.0.1:8000 in your browser.

Upgrade BitChan
---------------

Upgrading BitChan can be performed with the following commands. Any database schema changes will be automatically performed. If a new version is incompatible with your previous version and the database cannot be upgraded, you will need to `delete both docker volumes <#deleting-volumes>`__ before running ``make daemon``. Note: Deleting both volumes will delete all data. To determine if you need to delete any volumes to run any newer version, refer to `CHANGELOG.md <CHANGELOG.md>`__.

.. code::

    cd BitChan
    git pull
    cd docker
    sudo make daemon


Docker and Control Options
==========================

Backup and Restore BitChan
--------------------------

You can save the state of Bitmessage and BitChan and restore it on another machine. This will preserve everything exactly as it was, including boards, lists, threads, messages, attachments, address book, identities, etc. With BitChan running, execute the following commands.

 - Create backup and transfer to your local machine:

.. code::

    sudo docker exec -it bitchan_flask tar -cvf /home/bitchan/bitchan_backup-usr_bitchan.tar /usr/local/bitchan
    sudo docker exec -it bitchan_flask tar -cvf /home/bitchan/bitchan_backup-usr_bitmessage.tar /usr/local/bitmessage
    sudo docker exec -it bitchan_flask tar -cvf /home/2021_07_01_bitchan-backup.tar /home/bitchan
    sudo docker cp bitchan_flask:/home/2021_07_01_bitchan-backup.tar ~/
    sudo docker exec -it bitchan_flask rm -rf /home/bitchan/bitchan_backup-usr_bitchan.tar /home/bitchan/bitchan_backup-usr_bitmessage.tar /home/2021_07_01_bitchan-backup.tar


 - Transfer backup to remote machine that has BitChan installed:

.. code::

    sudo docker cp ~/2021_07_01_bitchan-backup.tar bitchan_flask:/
    sudo docker exec -it bitchan_flask tar -xvf /2021_07_01_bitchan-backup.tar -C /
    sudo docker exec -it bitchan_flask tar -xvf /home/bitchan/bitchan_backup-usr_bitchan.tar -C /
    sudo docker exec -it bitchan_flask tar -xvf /home/bitchan/bitchan_backup-usr_bitmessage.tar -C /
    sudo docker exec -it bitchan_flask rm -rf /2021_07_01_bitchan-backup.tar /home/bitchan/bitchan_backup-usr_bitchan.tar /home/bitchan/bitchan_backup-usr_bitmessage.tar


 - Restart BitChan

.. code::

    cd BitChan/docker
    sudo docker-compose down
    sudo make daemon


Docker Container Networking
---------------------------

- nginx container (BitChan Web User Interface)

  - IP: 172.28.1.1
  - Port: 8000
  - Address: http://172.28.1.1:8000

- tor container

  - IP: 172.28.1.2
  - Proxy Port: 9060
  - Control Port: 9061

- bitmessage container

  - IP: 172.28.1.3
  - Port: 8445

- bitchan_flask container (frontend)

  - IP: 172.28.1.4

- bitchan_daemon container (backend)

  - IP: 172.28.1.5

Adding User to Docker Group
---------------------------

Add your user to the docker group to run docker as a non-root user.

.. code::

    sudo groupadd docker
    sudo usermod -aG docker $USER


Log out and back in for the group addition to take effect.

Make sure you're in the BitChan/docker directory when executing the ``make`` or ``docker-compose`` commands.

Build and Daemonize (runs as daemon at startup)
-----------------------------------------------

``make daemon``

Build and Bring Up (output to stdout)
-------------------------------------

``make build``

Stop and delete containers
--------------------------

``make clean``

Bring Down
----------

``docker-compose down``

Bring Up (stdout)
-----------------

``docker-compose up``

Bring Up (daemon)
-----------------

``docker-compose up -d``

Build and Bring Up (stdout)
---------------------------

Note: same as ``make build`` command

``docker-compose up --build``

Build and Bring Up (daemon)
---------------------------

Note: same as ``make daemon`` command

``docker-compose up --build -d``

Accessing volumes
-----------------

To access the volumes as your user, first change ownership to be able to access docker volumes.

``sudo chown -R $USER /var/lib/docker``

Access bitchan volume
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``ls -la /var/lib/docker/volumes/docker_bitchan/_data/``

Access bitmessage volume
~~~~~~~~~~~~~~~~~~~~~~~~

``ls -la /var/lib/docker/volumes/docker_bitmessage/_data/``

Deleting volumes
----------------

Delete BitChan volume
~~~~~~~~~~~~~~~~~~~~~

*Note: This will also delete the BitChan database*

.. code::

    cd BitChan/docker
    docker-compose down
    docker volume rm docker_bitchan


Delete Bitmessage volume
~~~~~~~~~~~~~~~~~~~~~~~~

Note: This will delete the Bitmessage keys.dat and messages.dat

.. code::

    cd BitChan/docker
    docker-compose down
    docker volume rm docker_bitmessage


Tor Control
-----------

To use nyx to connect to the control port of the containerized tor, run the following from a linux terminal on the system running the docker containers.

.. code::

    sudo apt install nyx
    nyx -i 172.28.1.2:9061


Enter password torpass1234

Note: To change the default tor password, edit BitChan/docker/docker-compose.yml and change ``password: "torpass1234"`` to something else, then rebuild your containers with ``make daemon``


Virtual Private Server / Kiosk Mode
===================================

Installing and running BitChan on a debian-based virtual private server (VPS) is very easy and allows BitChan to be publicly accessible. However, as with all public systems, security should be a significant concern. Therefore, a Kiosk Mode has been created that institutes a login and permission system to allow administration as well as anonymous posting, among other features. Furthermore, the hosting of hidden onion services has been built-in to allow secure and anonymous access to your BitChan instance. See the `Kiosk Mode <MANUAL.md#kiosk-mode>`__ and `Hidden Onion Service <MANUAL.md#hidden-onion-service>`__ sections of the manual for more information.

Installing and Running
----------------------

Securely log in to your VPS, changing "123.123.123.123" to the VPS IP address and "user" to your user:

.. code::

    torsocks ssh user@123.123.123.123


Then follow the [Install Instructions](#install-on-debian-based-operating-systems).

Before building, if you are going to have this install publicly accessible on the internet, you may want to enable kiosk mode and add an admin user. This can be done by setting the Admin password in BitChan/credentials.py and enabling Kiosk Mode on the configuration menu of the UI. This will require logging in with the password to make changes to the system. You can also change the Kiosk settings in config.py, such as to disable anonymous posting.

After building and once running, go to http://123.123.123.123:8000 to access the system and check if your password works to log in. If you want to prevent access via the IP address, you will need to first enable a tor hidden onion service, then disable HTTP access. First, enable the tor hidden onion service from the Configuration page. After a minute, verify you can connect to the onion address listed on the configuration page with tor browser. Last, disable HTTP access, by editing BitChan/docker/docker-componse.yaml and commenting out the nginx port section in order to disable exposing port 8000.

.. code::

    ports:
      - "8000:8000"


To:

.. code::

    # ports:
    #   - "8000:8000"


Save, then rebuild BitChan:

.. code::

    cd BitChan/docker
    make daemon


Once rebuilt, you should only be able to access BitChan from the hidden onion address in tor browser. If you want to use a custom onion address, you can generate a v3 onion address and provide the credentials in a zip file. This will allow you to host BitChan on both a randomly-created onion address and a custom vanity address. The random address can be kept private and used for maintenance/testing/administration and the custom address can be given out publicly for users to use the system. If you ever need to temporarily disable access to the system, you can disable the custom address and keep the random address enabled in order to maintain your own private access.


Upgrading to a New Version
--------------------------

These steps assume there's already an install of BitChan running on the VPS. Download latest version locally as bitchan.tar.gz, then upload securely to VPS, changing "123.123.123.123" to the VPS IP address and "user" to your user:

.. code::

    torsocks scp bitchan.tar.gz user@123.123.123.123:/user


Login securely to VPS, then copy relevant files to new version and rebuild. Note: Since newer versions of BitChan may have changes made to docker-compose.yml, config.py, or credentials.py, it's advisable to manually make changes to the newer version's config files, as blindly overwriting them may break functionality in the newer version. The use of the commands below assume it's safe to overwrite these files.

.. code::

    torsocks ssh user@123.123.123.123
    mv /user/bitchan /user/bitchan-old
    mkdir /user/bitchan
    tar zxf /user/bitchan.tar.gz --strip-components=1 -C /user/bitchan
    cp /user/bitchan-old/docker/docker-compose.yml /user/bitchan/docker/
    cp /user/bitchan-old/config.py /user/bitchan/
    cp /user/bitchan-old/credentials.py /user/bitchan/
    cd /user/bitchan/docker
    make daemon


Troubleshooting
===============

If your system spontaneously shuts down, you may find upon restarting, nginx producing the following error:

nginx: [emerg] bind() to unix:/usr/local/nginx/nginx.sock failed (98: Address already in use)

If this occurs, stop the docker containers, delete the nginx volume, then build:

.. code::

    cd BitChan/docker
    docker-compose down
    docker volume rm docker_nginx
    make daemon


Donate
======

Monero Address
--------------

49KE6mo43c6DLuszW48ZkYG8x6KcxjhscY5KzsNLTqLk8Vw2gBaTnoggxfYLJnQ95zNuDpfFESYSFZoucYq5vWAjNrqHbhX

Developer Information
=====================

BitChan GitHub Repository: `github.com/813492291816/BitChan <https://github.com/813492291816/BitChan>`__

Bitmessage Mail: address ``BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ``

Bitmessage Chan: passphrase "bitchan" without quotes, verify the address is ``BM-2cT6NKM8PZvgkdd8JZ3Z9r9u2sb3jbkCAf``

E-Mail: `BitChan@mailchuck.com <mailto:bitchan@mailchuck.com>`__

*Note: This email can only receive messages. Use Bitmessage for 2-way communication.*

PGP Public Key: `E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC <https://keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC>`__
