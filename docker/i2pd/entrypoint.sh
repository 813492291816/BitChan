#!/bin/sh
COMMAND=/usr/local/bin/i2pd
DEFAULT_ARGS=" --datadir=$DATA_DIR --upnp.enabled=false"

mv /home/i2pd/i2pd.conf /home/i2pd/data/i2pd.conf

ln -s /i2pd_certificates "$DATA_DIR"/certificates
set -- $COMMAND $DEFAULT_ARGS $@

chown -R i2pd:nobody "$I2PD_HOME"

su - i2pd

exec "$@"
