FROM purplei2p/i2pd:latest

RUN mkdir -p /home/i2pd/data

COPY docker/i2pd/i2pd.conf /home/i2pd/data/i2pd.conf

# Set up the HTTP tunnel
#COPY docker/i2pd/tunnels.conf /home/i2pd/data/tunnels.conf

# If you have a private key for a tunnel, place it in this directory,
# set the file name in tunnels.conf, and uncomment the lines above and below.
# If you don't have have a private key file, one will be generated
#COPY docker/i2pd/bitchan-tunnel.dat /home/i2pd/data/bitchan-tunnel.dat
