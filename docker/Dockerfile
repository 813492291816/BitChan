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
RUN mkdir -p /usr/local/bitchan
RUN mkdir -p /usr/local/bitchan/log
RUN mkdir -p /usr/local/bitchan/downloaded_files
RUN chown bitchan /home/bitchan
RUN chown bitchan /usr/local/gnupg

# Apt dependencies
COPY ./docker/install_packages.sh /home/bitchan/install_packages.sh
RUN /bin/bash /home/bitchan/install_packages.sh

# Upgrade pips
RUN python2 -m pip install --no-cache-dir --upgrade pip
RUN python3 -m pip install --no-cache-dir --upgrade pip


#
# Bitmessage
#

# Bitmessage pip dependencies
COPY ./requirements_bitmessage.txt /home/bitchan/requirements-bitmessage.txt
RUN python2 -m pip install --no-cache-dir -r /home/bitchan/requirements-bitmessage.txt
RUN rm -f /home/bitchan/requirements-bitmessage.txt

# Run Bitmessage clone script (gets bitmessage)
COPY ./docker/bitmessage/bitmessage_clone.sh /home/bitchan/bitmessage_clone.sh
RUN /bin/bash /home/bitchan/bitmessage_clone.sh
RUN rm -f /home/bitchan/bitmessage_clone.sh

# Bitmessage pip dependencies and installation
RUN python2 -m pip install --no-cache-dir -r /home/bitchan/PyBitmessage/requirements.txt
RUN cd /home/bitchan/PyBitmessage && python2 setup.py install


#
# Bitchan
#

# BitChan pip dependencies
COPY ./requirements.txt /home/bitchan/requirements-bitchan.txt
RUN python3 -m pip install --no-cache-dir -r /home/bitchan/requirements-bitchan.txt
RUN rm -f /home/bitchan/requirements-bitchan.txt

# Install BitChan
RUN cd ${HOME}
COPY . /home/bitchan/
RUN chown -R bitchan /usr/local/bitchan
