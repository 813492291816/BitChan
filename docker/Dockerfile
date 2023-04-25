FROM debian:bullseye-slim

# Bitmessage environment varaibles
ENV BITMESSAGE_HOME /usr/local/bitmessage
ENV VER 0.6.3.2

# Bitchan environment variables
ENV DOCKER TRUE
ENV HOME /home/bitchan

ENV DEBIAN_FRONTEND noninteractive

WORKDIR ${HOME}

RUN useradd bitchan

RUN mkdir -p /usr/local/gnupg
RUN mkdir -p /usr/local/bitmessage
RUN mkdir -p /usr/local/bitchan
RUN mkdir -p /usr/local/bitchan/log
RUN mkdir -p /usr/local/bitchan/downloaded_files
RUN chown bitchan /usr/local/bitmessage
RUN chown bitchan /home/bitchan
RUN chown bitchan /usr/local/gnupg

# Apt dependencies
COPY ./install_packages.sh /home/bitchan/install_packages.sh
RUN /bin/bash /home/bitchan/install_packages.sh

# Upgrade pips
RUN python2 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pip

#
# Tor
#

COPY ./install_tor.sh /home/bitchan/install_tor.sh
RUN /bin/bash /home/bitchan/install_tor.sh

RUN mkdir -p /usr/local/tor
RUN mkdir -p /usr/local/tor/bm
RUN mkdir -p /usr/local/tor/cus
RUN mkdir -p /usr/local/tor/rand
RUN mkdir -p /usr/local/tor/authorized_clients/
RUN mkdir -p /root/.tor
RUN chown -R root /root/.tor

COPY docker/tor/torrc /usr/local/tor/torrc

COPY ./docker/tor/torpass.sh /home/bitchan/torpass.sh
RUN /bin/bash /home/bitchan/torpass.sh

RUN chmod -R 700 /usr/local/tor
RUN chown -R root /usr/local/tor

#
# Bitmessage
#

# Bitmessage pip dependencies
COPY ./requirements_bitmessage.txt /home/bitchan/requirements-bitmessage.txt
RUN python2 -m pip install -r /home/bitchan/requirements-bitmessage.txt
RUN rm -f /home/bitchan/requirements-bitmessage.txt

# Run Bitmessage clone script (gets bitmessage)
COPY ./docker/bitmessage_clone.sh ./bitmessage_clone.sh
RUN /bin/bash /home/bitchan/bitmessage_clone.sh
RUN rm -f /home/bitchan/bitmessage_clone.sh

# Bitmessage pip dependencies and installation
RUN python2 -m pip install -r /home/bitchan/PyBitmessage/requirements.txt
RUN cd /home/bitchan/PyBitmessage && python2 setup.py install

# Generate Bitmessage /usr/local/bitmessage/keys.dat)
COPY ./docker/bitmessage_setup.sh ./bitmessage_setup.sh
COPY ./install_files/knownnodes.dat ./knownnodes.dat
RUN /bin/bash /home/bitchan/bitmessage_setup.sh
RUN rm -f /home/bitchan/bitmessage_setup.sh

#
# Bitchan
#

# BitChan pip dependencies
COPY ./requirements.txt /home/bitchan/requirements-bitchan.txt
RUN python3 -m pip install -r /home/bitchan/requirements-bitchan.txt
RUN rm -f /home/bitchan/requirements-bitchan.txt

# Install BitChan
RUN cd ${HOME}
COPY . /home/bitchan/
RUN chown -R bitchan /usr/local/bitchan
RUN chown -R bitchan /usr/local/bitmessage
