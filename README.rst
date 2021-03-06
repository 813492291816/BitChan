=======
BitChan
=======

Version: 0.11.0

BitChan is a decentralized anonymous image board inspired by `BitBoard <https://github.com/michrob/bitboard>`__ and built on top of `Bitmessage <https://bitmessage.org>`__ with `Tor <https://www.torproject.org>`__ and `GnuPG <https://gnupg.org>`__.

Bitmessage is a decentralized, encrypted messaging application. It relies on public key encryption (similar to PGP), decentralized message delivery, which due to the nature of every message being distributed to every client, also provides plausible deniability (i.e. no one knows who the message was intended to go to). BitChan runs on top of Bitmessage to enhance its functionality and security, by providing a feature-rich frontend to what is normally a text-based experience. BitChan offers boards for a forum-like experience with image and file sharing, lists to organize and share other boards and lists, along with a host of additional features to enhance posts and provide board and list management with the use of owner, admin, and user permissions. Boards and lists can be public or private, with or without owners or admins, allowing a full range from completely unmoderatable to strictly allowing only select addresses to post or modify list contents.

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

  - All internet traffic (Bitmessage/uploads/downloads) through tor with fake UserAgent
  - All messages PGP-encrypted with user-selectable cipher and key length
  - Encryption, fragmentation, and hashing to secure and verify authenticity of received post attachment files
  - Bitmessage Identities for private addresses that only you control

- Mailbox system for messaging other Bitmessage addresses

  - Read, delete, reply, and forward messages
  - Message composition page to send messages
  - Send a message directly from a board to a post's address

- Boards for posting messages and Lists for sharing other boards and lists

  - Permissions for board/list ownership and administration
  - Public access where anyone can post on a board or add to a list
  - Private access where only select addresses can post or modify a list
  - Several user permissions (Owners, Admins, Users, and Restricted)
  - Rules to allow board/list Owners to determine if certain features are enabled
  - Owner options to set long description, banner and spoiler images, word replacements, custom CSS
  - Address Book to saved addresses and labels will appear next to those addresses

- Board Features

  - Post with any Bitmessage address you can send from
  - Threaded posting with text enhancements
  - Embed images/videos in posts
  - Images and videos in posts expand to full-width on click

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

- Database upgrade system to automatically upgrade BitChan database to new schemas

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

The following steps are to install BitChan on a Debian-based operating system. This has been tested on `Xubuntu <https://xubuntu.org>`__ 20.04 and `Whonix <https://www.whonix.org>`__ 15.0.1.5.1 as virtual machines in `VirtualBox <https://www.virtualbox.org/>`__. Open a terminal and run the following commands:

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
  - Port: 8000
  - Address: http://172.28.1.1:8000

- tor

  - IP: 172.28.1.2
  - Proxy Port: 9060
  - Control Port: 9061

- Bitmessage API

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

Access Bitmessage volume
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

Donate
======

Monero Address
--------------

49KE6mo43c6DLuszW48ZkYG8x6KcxjhscY5KzsNLTqLk8Vw2gBaTnoggxfYLJnQ95zNuDpfFESYSFZoucYq5vWAjNrqHbhX

Developer Information
=====================

BitChan GitHub Repository: `github.com/813492291816/BitChan <https://github.com/813492291816/BitChan>`__

Bitmessage Address: ``BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ``

E-Mail: `BitChan@mailchuck.com <mailto:bitchan@mailchuck.com>`__

*Note: This email can only receive messages. Use Bitmessage for 2-way communication.*

PGP Public Key: `E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC <https://keys.openpgp.org/vks/v1/by-fingerprint/E90B33C4C0E73AF537F2C2E9B14DF20410E5A5BC>`__
