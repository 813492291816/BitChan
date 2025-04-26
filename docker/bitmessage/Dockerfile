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

RUN chown bitchan /home/bitchan

# Apt dependencies
COPY ./docker/bitmessage/install_packages_bitmessage.sh /home/bitchan/install_packages_bitmessage.sh
RUN /bin/bash /home/bitchan/install_packages_bitmessage.sh
RUN rm -f /home/bitchan/install_packages_bitmessage.txt

# Install/upgrade pip
COPY ./docker/bitmessage/install_pip2.sh /home/bitchan/install_pip2.sh
RUN /bin/bash /home/bitchan/install_pip2.sh
RUN rm -f /home/bitchan/install_pip2.txt

#
# Bitmessage
#

# Bitmessage pip dependencies
RUN python2 -m pip install virtualenv
RUN python2 -m virtualenv /home/bitchan/env2
COPY ./install_files/bitmessage/requirements-freeze-hashes.txt /home/bitchan/requirements_bitmessage_copy.txt
RUN /home/bitchan/env2/bin/python2 -m pip install --require-hashes --no-deps --no-cache-dir -r /home/bitchan/requirements_bitmessage_copy.txt
RUN rm -f /home/bitchan/requirements_bitmessage_copy.txt

# Run Bitmessage clone script (gets bitmessage)
COPY ./docker/bitmessage/bitmessage_clone.sh /home/bitchan/bitmessage_clone.sh
RUN /bin/bash /home/bitchan/bitmessage_clone.sh
RUN rm -f /home/bitchan/bitmessage_clone.sh

# Bitmessage installation
RUN cd /home/bitchan/PyBitmessage && /home/bitchan/env2/bin/python2 setup.py install

# Install BitChan
RUN cd ${HOME}
COPY .. /home/bitchan/
