=======
BitChan
=======

Version: 0.9.0

BitChan is a decentralized anonymous image board inspired by BitBoard and built on top of `BitMessage <https://bitmessage.org>`__ with `Tor <https://www.torproject.org>`__ and `GnuGP <https://gnupg.org>`__.

BitMessage is a decentralized, encrypted messaging application. It relies on public key encryption (similar to PGP), decentralized message delivery, which due to the nature of every message being distributed to every client, also provides plausible deniability (i.e. no one knows who the message was intended to go to). BitChan runs on top of BitMessage to enhance its functionality and security, by providing a feature-rich frontend to what is normally a text-based experience. BitChan offers boards for a forum-like experience with image and file sharing, lists to organize and share other boards and lists, along with a host of additional features to enhance posts and provide board and list management with the use of owner, admin, and user permissions. Boards and lists can be public or private, with or without owners or admins, allowing a full range from completely unmoderatable to strictly allowing only select addresses to post or modify list contents.

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

  - All internet traffic (BitMessage/uploads/downloads) through tor with fake UserAgent
  - All messages PGP-encrypted
  - MD5 hashing to verify authenticity of received post attachment files
  - Attachment files sent through an external upload site are added to a compressed and password-protected ZIP, then header and random parts of the ZIP are removed and sent within the encrypted BitMessage message (and subsequently put back together after each are received)

- BitMessage Identities and Address Book management pages

- Boards for posting messages and Lists for sharing other boards and lists

  - Permissions for board/list ownership and administration
  - Public where anyone can post on a board or add to a list
  - Private where only select addresses have write access
  - Several access levels (Owners, Admins, and Users)
  - Rules: Require Identity to Post, Automatic Wipe

- Board Features

  - Post with any BitMessage address (Identities or Chans)
  - Threaded posting with text enhancements
  - Embed images/videos in posts
  - Images and videos in posts expand to full-width on click

  - File Attachments

    - Can have any file type attached
    - Send through BitMessage (if file small enough, <= ~250 KB)
    - Support for external upload site (Anonfiles, Bayfiles, Forumfiles, Uplovd)
    - Support for post text replacements: dice (#3D20), cards (#C5), flip (#flip), 8ball (#8ball), tarot card (#t5), Crowley tarot (#ct5), random book quote (#stich)
    - Support for post text styles: @@bold@@, \~\~italic\~\~, \_\_underline\_\_, ++strikethrough++, ==big==, \*\*spoiler\*\*, ^s shadow ^s, [meme]meme[/meme], [autism]autism[/autism], [flash]flash[/flash], [aa]ascii art[/aa], and more

- Owner/Admin Commands

  - Owners can set a custom CSS, word replacements, and banner image
  - Board Owners/Admins can delete threads and posts (affects all users of a board)
  - Board Owners/Admins can ban users from posting (affects all users of a board)
  - Users can block address from posting to one or all boards (only local effects)

- Database upgrade system to automatically upgrade BitChan database to new schemas

Setup
=====

BitChan is distributed with a stable version of BitMessage and runs inside several docker containers that's orchestrated by docker-compose. This allows cross-platform compatibility and isolation of your install from your operating system. For a consistent install environment, installing BitChan within a virtual machine running Xubuntu 20.04 is described below, however you can install BitChan in any operating system of your choice.

Install BitChan
---------------

To install BitChan, first install `docker <https://docs.docker.com/get-docker/>`__ and `docker-compose <https://docs.docker.com/compose/install/>`__, then change to the BitChan/docker directory and execute:

.. code::

    docker-compose up --build -d


If you get a timeout error while downloading any of the docker image files, just run the command again until it successfully finishes all downloads.

Install on Debian-Based Operating Systems
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following steps are to install BitChan on a Debian-based operating system. This has been tested on `Xubuntu <https://xubuntu.org>`__ 20.04 and `Whonix <https://www.whonix.org>`__ 15.0.1.5.1 as virtual machines in `VirtualBox <https://www.virtualbox.org/>`__. Open a terminal and run the following commands:

.. code::

    sudo apt install git docker.io docker-compose build-essential
    sudo systemctl enable docker
    git clone https://github.com/813492291816/BitChan
    cd BitChan/docker
    sudo make daemon


Post-install
~~~~~~~~~~~~

BitChan will automatically start at boot (if enabled) and runs on port 80 by default, which can be accessed by visiting http://localhost or http://172.28.1.1 in a web browser.

For added security, it's recommended to either A) use tor browser or B) configure another browser to connect through tor.

- A: Tor Browser: Install tor browser (``sudo apt install torbrowser-launcher``). Launch tor browser and enter ``about:config`` in the address bar. Search for ``network.proxy.no_proxies_on`` and enter ``172.28.1.1`` to exclude the BitChan IP address from the proxy. Open BitChan at ``http://172.28.1.1``.

- B: Configure your browser to use the Tor SOCKS5 proxy with the host ``172.28.1.2`` and port 9060 (the IP and port for tor running in the tor docker container). Open BitChan at ``http://localhost``.

Verify your browser is using tor by visiting `https://check.torproject.org <https://check.torproject.org>`__.

*Note: If using http://127.0.0.1 or http://172.28.1.1, the embedded youtube player will not work, unless you're using tor browser. Using http://localhost will allow it to work, but this address cannot be accessed with tor browser.*

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

Docker Container Networking
---------------------------

- BitChan Web User Interface

  - IP: 172.28.1.1
  - Port: 80
  - Address: http://172.28.1.1

- tor

  - IP: 172.28.1.2
  - Proxy Port: 9050
  - Control Port: 9061

- BitMessage API

  - IP: 172.28.1.3
  - Port: 8445

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

Access BitChan volume
~~~~~~~~~~~~~~~~~~~~~

``ls -la /var/lib/docker/volumes/docker_bitchan/_data/``

Access BitMessage volume
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


Delete BitMessage volume
~~~~~~~~~~~~~~~~~~~~~~~~

Note: This will delete the BitMessage keys.dat and messages.dat

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

Developer Information
=====================

BitChan GitHub Repository: `github.com/813492291816/BitChan <https://github.com/813492291816/BitChan>`__

BitMessage Address: ``BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ``

E-Mail: `BitChan@mailchuck.com <mailto:bitchan@mailchuck.com>`__

*Note: This email can only receive messages. Use BitMessage to have 2-way communication.*

PGP Public Key:

.. code::

    -----BEGIN PGP PUBLIC KEY BLOCK-----

    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
    =dZAw
    -----END PGP PUBLIC KEY BLOCK-----
