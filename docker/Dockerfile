FROM python:3.8-slim-buster

# Bitmessage environment varaibles
ENV BITMESSAGE_HOME /usr/local/bitmessage
ENV VER 0.6.3.2

# Bitchan environment variables
ENV DOCKER TRUE
ENV HOME /home/bitchan

ENV DEBIAN_FRONTEND noninteractive

WORKDIR ${HOME}

RUN useradd bitchan

RUN mkdir -p /usr/local/bitmessage
RUN mkdir -p /usr/local/bitchan
RUN mkdir -p /usr/local/bitchan/log
RUN mkdir -p /usr/local/bitchan/downloaded_files
RUN chown bitchan /usr/local/bitmessage
RUN chown bitchan /home/bitchan

# Apt dependencies
COPY ./install_packages.sh /home/bitchan/install_packages.sh
RUN /bin/bash /home/bitchan/install_packages.sh
RUN rm -f /home/bitchan/requirements-bitmessage.txt

# Upgrade pips
RUN pip2 install --upgrade pip
RUN pip3 install --upgrade pip

#
# Bitmessage
#

# Bitmessage pip dependencies
COPY ./requirements_bitmessage.txt /home/bitchan/requirements-bitmessage.txt
RUN pip2 install -r /home/bitchan/requirements-bitmessage.txt
RUN rm -f /home/bitchan/requirements-bitmessage.txt
# Run Bitmessage clone script (gets bitmessage)
COPY ./docker/bitmessage_clone.sh ./bitmessage_clone.sh
RUN /bin/bash /home/bitchan/bitmessage_clone.sh
RUN rm -f /home/bitchan/bitmessage_clone.sh
# Bitmessage pip dependencies and installation
RUN pip2 install -r /home/bitchan/PyBitmessage/requirements.txt
RUN cd /home/bitchan/PyBitmessage && python2 setup.py install
# Generate Bitmessage /usr/local/bitmessage/keys.dat)
COPY ./docker/bitmessage_setup.sh ./bitmessage_setup.sh
RUN /bin/bash /home/bitchan/bitmessage_setup.sh
RUN rm -f /home/bitchan/bitmessage_setup.sh

#
# Bitchan
#

# BitChan pip dependencies
COPY ./requirements.txt /home/bitchan/requirements-bitchan.txt
RUN pip3 install -r /home/bitchan/requirements-bitchan.txt
RUN rm -f /home/bitchan/requirements-bitchan.txt

# Install BitChan
RUN cd ${HOME}
COPY . /home/bitchan/
RUN chown -R bitchan /usr/local/bitchan
RUN chown -R bitchan /usr/local/bitmessage
