import json
import logging
import sqlite3
from binascii import unhexlify

import config

logger = logging.getLogger('bitchan.shared')


def get_msg_expires_time(msg_id: str):
    try:
        conn = sqlite3.connect('file:{}?mode=ro'.format(
            config.messages_dat), uri=True, check_same_thread=False)
        conn.text_factory = bytes
        c = conn.cursor()
        c.execute('SELECT expirestime FROM inventory WHERE hash=?', (unhexlify(msg_id),))
        data = c.fetchall()
        if data:
            return data[0][0]
    except Exception:
        logger.exception("except {}".format(msg_id))
        return


def is_access_same_as_db(options, chan_entry):
    """Check if command access same as chan access"""
    return_dict = {
        "secondary_access": False,
        "tertiary_access": False,
        "restricted_access": False
    }

    if "modify_admin_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_admin_addresses"])
        chan = sorted(json.loads(chan_entry.secondary_addresses))
        if command == chan:
            return_dict["secondary_access"] = True

    if "modify_user_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_user_addresses"])
        chan = sorted(json.loads(chan_entry.tertiary_addresses))
        if command == chan:
            return_dict["tertiary_access"] = True

    if "modify_restricted_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_restricted_addresses"])
        chan = sorted(json.loads(chan_entry.restricted_addresses))
        if command == chan:
            return_dict["restricted_access"] = True

    return return_dict


def get_combined_access(command, chan):
    """Return chan access, with admin command taking priority"""
    access = {}
    if chan:
        try:
            access["primary_addresses"] = json.loads(chan.primary_addresses)
        except:
            access["primary_addresses"] = []

        try:
            access["secondary_addresses"] = json.loads(chan.secondary_addresses)
        except:
            access["secondary_addresses"] = []

        try:
            access["tertiary_addresses"] = json.loads(chan.tertiary_addresses)
        except:
            access["tertiary_addresses"] = []

        try:
            access["restricted_addresses"] = json.loads(chan.restricted_addresses)
        except:
            access["restricted_addresses"] = []

        if command:
            try:
                options = json.loads(command.options)
            except:
                options = {}
            if "modify_admin_addresses" in options:
                access["secondary_addresses"] = options["modify_admin_addresses"]
            if "modify_user_addresses" in options:
                access["tertiary_addresses"] = options["modify_user_addresses"]
            if "modify_restricted_addresses" in options:
                access["restricted_addresses"] = options["modify_restricted_addresses"]
    return access
