"""Tor specific procedures"""
import logging
import os
import stat
import random
import tempfile

import stem
import stem.control
import stem.process
import stem.util
import stem.version

from . import shared


def logwrite(line):
    """A simple log writing handler for tor messages"""
    try:
        level, line = line.split('[', 1)[1].split(']', 1)
    except (IndexError, ValueError):
        logging.warning(line)
    else:
        if level in ('err', 'warn'):
            logging.info('(tor)%s', line)


def start_tor_service():
    """Start own tor instance and configure a hidden service"""
    try:
        socket_dir = os.path.join(shared.data_directory, 'tor')
        os.makedirs(socket_dir, exist_ok=True)
    except OSError:
        try:
            socket_dir = tempfile.mkdtemp()
        except OSError:
            logging.info('Failed to create a temp dir.')
            return

    if os.getuid() == 0:
        logging.info('Tor is not going to start as root')
        return

    try:
        present_permissions = os.stat(socket_dir)[0]
        disallowed_permissions = stat.S_IRWXG | stat.S_IRWXO
        allowed_permissions = ((1 << 32) - 1) ^ disallowed_permissions
        os.chmod(socket_dir, allowed_permissions & present_permissions)
    except OSError:
        logging.debug('Failed to set dir permissions.')
        return

    stem.util.log.get_logger().setLevel(logging.WARNING)

    control_socket = os.path.abspath(os.path.join(socket_dir, 'tor_control'))
    port = str(shared.socks_proxy.port)
    tor_config = {
        'SocksPort': port,
        'ControlSocket': control_socket}

    for attempt in range(20):
        if attempt > 0:
            port = random.randint(32767, 65535)  # nosec B311
            tor_config['SocksPort'] = str(port)
        try:
            stem.process.launch_tor_with_config(
                tor_config, take_ownership=True, timeout=90,
                init_msg_handler=logwrite)
        except OSError:
            if not attempt:
                if not shared.listen_for_connections:
                    return
                try:
                    stem.version.get_system_tor_version()
                except IOError:
                    return
            continue
        else:
            logging.info('Started tor on port %s', port)
            break
    else:
        logging.debug('Failed to start tor.')
        return

    if not shared.listen_for_connections:
        return True

    try:
        controller = stem.control.Controller.from_socket_file(control_socket)
        controller.authenticate()
    except stem.SocketError:
        logging.debug('Failed to instantiate or authenticate on controller.')
        return

    onionkey = onionkeytype = None
    try:
        with open(
            os.path.join(shared.data_directory, 'onion_dest_priv.key'),
            'r', encoding='ascii'
        ) as src:
            onionkey = src.read()
            logging.debug('Loaded onion service private key.')
        onionkeytype = 'ED25519-V3'
    except FileNotFoundError:
        pass
    except Exception:
        logging.info(
            'Error while loading onion service private key.', exc_info=True)

    response = controller.create_ephemeral_hidden_service(
        shared.listening_port, key_type=onionkeytype or 'NEW',
        key_content=onionkey or 'BEST'
    )

    if not response.is_ok():
        logging.info('Bad response from controller ):')
        return

    shared.onion_hostname = '{}.onion'.format(response.service_id)
    logging.info('Started hidden service %s', shared.onion_hostname)

    if onionkey:
        return controller

    try:
        with open(
            os.path.join(shared.data_directory, 'onion_dest_priv.key'),
            'w', encoding='ascii'
        ) as src:
            src.write(response.private_key)
            logging.debug('Saved onion service private key.')
    except Exception:
        logging.warning(
            'Error while saving onion service private key.', exc_info=True)

    try:
        with open(
            os.path.join(shared.data_directory, 'onion_dest.pub'),
            'w', encoding='ascii'
        ) as src:
            src.write(response.service_id)
            logging.debug('Saved onion service public key.')
    except Exception:
        logging.warning(
            'Error while saving onion service public key.', exc_info=True)

    return controller
