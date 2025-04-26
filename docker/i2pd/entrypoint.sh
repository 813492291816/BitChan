#!/bin/sh
COMMAND=/usr/local/bin/i2pd
DEFAULT_ARGS=" --datadir=$DATA_DIR --upnp.enabled=false"

mv /home/i2pd/i2pd.conf /home/i2pd/data/i2pd.conf

# Generate random password for i2pd webconsole
# Command to view user/pass:
# docker exec -it bitchan_i2p sh -c "cat /home/i2pd/data/i2pd.conf"
I2PDPASS=$(tr -dc a-zA-Z0-9 < /dev/urandom | head -c32 && echo)
export I2PDPASS
sed -i "/pass = bci2ppass/c\pass = $I2PDPASS" /home/i2pd/data/i2pd.conf

ln -s /i2pd_certificates "$DATA_DIR"/certificates
set -- $COMMAND $DEFAULT_ARGS $@

chown -R i2pd:nobody "$I2PD_HOME"

su - i2pd

exec "$@"
