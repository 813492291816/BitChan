# -*- coding: utf-8 -*-
"""Functions for starting the program"""
import argparse
import base64
import logging
import multiprocessing
import os
import re
import signal
import socket
from urllib import parse

try:
    import socks
except ImportError:
    socks = None

from . import i2p, shared, sql
from .advertiser import Advertiser
from .manager import Manager
from .listener import Listener


def handler(s, f):  # pylint: disable=unused-argument
    """Signal handler"""
    logging.info('Gracefully shutting down MiNode')
    shared.shutting_down = True


def parse_arguments():  # pylint: disable=too-many-branches,too-many-statements
    """Parsing arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', help='Port to listen on', type=int)
    parser.add_argument('--host', help='Listening host')
    parser.add_argument(
        '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--data-dir', help='Path to data directory')
    parser.add_argument(
        '--no-incoming', action='store_true',
        help='Do not listen for incoming connections')
    parser.add_argument(
        '--no-outgoing', action='store_true',
        help='Do not send outgoing connections')
    parser.add_argument(
        '--no-ip', action='store_true', help='Do not use IP network')
    parser.add_argument(
        '--trusted-peer', help='Specify a trusted peer we should connect to')
    parser.add_argument(
        '--connection-limit', type=int, help='Maximum number of connections')
    parser.add_argument(
        '--i2p', action='store_true', help='Enable I2P support (uses SAMv3)')
    parser.add_argument(
        '--i2p-tunnel-length', type=int, help='Length of I2P tunnels')
    parser.add_argument(
        '--i2p-sam-host', help='Host of I2P SAMv3 bridge')
    parser.add_argument(
        '--i2p-sam-port', type=int, help='Port of I2P SAMv3 bridge')
    parser.add_argument(
        '--i2p-transient', action='store_true',
        help='Generate new I2P destination on start')

    if socks is not None:
        parser.add_argument(
            '--socks-proxy',
            help='SOCKS proxy address in the form <HOST>:<PORT>')
        parser.add_argument(
            '--tor', action='store_true',
            help='The SOCKS proxy is tor, use 127.0.0.1:9050 if not specified,'
            ' start tor and setup a hidden service'
        )

    args = parser.parse_args()
    if args.port:
        shared.listening_port = args.port
    if args.host:
        shared.listening_host = args.host
    if args.debug:
        shared.log_level = logging.DEBUG
    if args.data_dir:
        dir_path = args.data_dir
        if not dir_path.endswith('/'):
            dir_path += '/'
        shared.data_directory = dir_path
    if args.no_incoming:
        shared.listen_for_connections = False
    if args.no_outgoing:
        shared.send_outgoing_connections = False
    if args.no_ip:
        shared.ip_enabled = False
    if args.trusted_peer:
        if len(args.trusted_peer
               ) > 50 and not args.trusted_peer.endswith('onion'):
            # I2P
            shared.trusted_peer = (args.trusted_peer.encode(), 'i2p')
        else:
            colon_count = args.trusted_peer.count(':')
            if colon_count == 0:
                shared.trusted_peer = (args.trusted_peer, 8444)
            if colon_count == 1:
                addr = args.trusted_peer.split(':')
                shared.trusted_peer = (addr[0], int(addr[1]))
            if colon_count >= 2:
                # IPv6 <3
                addr = args.trusted_peer.split(']:')
                addr[0] = addr[0][1:]
                shared.trusted_peer = (addr[0], int(addr[1]))
    if args.connection_limit:
        shared.connection_limit = args.connection_limit
    if args.i2p:
        shared.i2p_enabled = True
    if args.i2p_tunnel_length:
        shared.i2p_tunnel_length = args.i2p_tunnel_length
    if args.i2p_sam_host:
        shared.i2p_sam_host = args.i2p_sam_host
    if args.i2p_sam_port:
        shared.i2p_sam_port = args.i2p_sam_port
    if args.i2p_transient:
        shared.i2p_transient = True

    if socks is None:
        return
    if args.tor:
        shared.tor = True
        if not args.socks_proxy:
            args.socks_proxy = '127.0.0.1:9050'
    if args.socks_proxy:
        if not re.match(r'^.*://', args.socks_proxy):
            args.socks_proxy = '//' + args.socks_proxy
        shared.socks_proxy = parse.urlparse(args.socks_proxy, scheme='socks5')


def bootstrap_from_dns():
    """Addes addresses of bootstrap servers to core nodes"""
    try:
        for port in (8080, 8444):
            for item in socket.getaddrinfo(
                'bootstrap{}.bitmessage.org'.format(port), 80,
                proto=socket.IPPROTO_TCP
            ):
                try:
                    addr = item[4][0]
                    socket.inet_pton(item[0], addr)
                except (TypeError, socket.error):
                    continue
                else:
                    shared.core_nodes.add((addr, port))
    except socket.gaierror:
        logging.info('Failed to do a DNS query')
    except Exception:
        logging.info('Error during DNS bootstrap', exc_info=True)


def start_ip_listener():
    """Starts `.listener.Listener`"""
    listener_ipv4 = None
    listener_ipv6 = None

    if socket.has_ipv6:
        try:
            listener_ipv6 = Listener(
                shared.listening_host,
                shared.listening_port, family=socket.AF_INET6)
            listener_ipv6.start()
        except socket.gaierror as e:
            if e.errno == -9:
                logging.info('IPv6 is not supported.')
        except Exception:
            logging.info(
                'Error while starting IPv6 listener on port %s',
                shared.listening_port, exc_info=True)

    try:
        listener_ipv4 = Listener(shared.listening_host, shared.listening_port)
        listener_ipv4.start()
    except OSError as e:
        if listener_ipv6:
            logging.info(
                'Error while starting IPv4 listener on port %s.'
                ' However the IPv6 one seems to be working'
                ' and will probably accept IPv4 connections.',  # 48 on macos
                shared.listening_port, exc_info=e.errno not in (48, 98))
        else:
            logging.warning(
                'Error while starting IPv4 listener on port %s.'
                'You will not receive incoming connections.'
                ' Please check your port configuration',
                shared.listening_port, exc_info=True)


def start_i2p_listener():
    """Starts I2P threads"""
    # Grab I2P destinations from old object file
    for obj in shared.objects.filter(object_type=shared.i2p_dest_obj_type):
        shared.i2p_unchecked_node_pool.add((
            base64.b64encode(obj.object_payload, altchars=b'-~'), 'i2p'))

    dest_priv = b''

    if not shared.i2p_transient:
        try:
            with open(
                os.path.join(shared.data_directory, 'i2p_dest_priv.key'), 'br'
            ) as src:
                dest_priv = src.read()
                logging.debug('Loaded I2P destination private key.')
        except FileNotFoundError:
            pass
        except Exception:
            logging.info(
                'Error while loading I2P destination private key.',
                exc_info=True)

    logging.info(
        'Starting I2P Controller and creating tunnels. This may take a while.')
    i2p_controller = i2p.I2PController(
        shared, shared.i2p_sam_host, shared.i2p_sam_port, dest_priv)
    i2p_controller.start()

    shared.i2p_dest_pub = i2p_controller.dest_pub
    shared.i2p_session_nick = i2p_controller.nick

    logging.info('Local I2P destination: %s', shared.i2p_dest_pub.decode())
    logging.info('I2P session nick: %s', shared.i2p_session_nick.decode())

    logging.info('Starting I2P Listener')
    i2p_listener = i2p.I2PListener(shared, i2p_controller.nick, shared.i2p_sam_host, shared.i2p_sam_port)
    i2p_listener.start()

    if not shared.i2p_transient:
        try:
            with open(
                os.path.join(shared.data_directory, 'i2p_dest_priv.key'), 'bw'
            ) as src:
                src.write(i2p_controller.dest_priv)
                logging.debug('Saved I2P destination private key.')
        except Exception:
            logging.warning(
                'Error while saving I2P destination private key.',
                exc_info=True)

    try:
        with open(
            os.path.join(shared.data_directory, 'i2p_dest.pub'), 'bw'
        ) as src:
            src.write(shared.i2p_dest_pub)
            logging.debug('Saved I2P destination public key.')
    except Exception:
        logging.warning(
            'Error while saving I2P destination public key.', exc_info=True)


def main():
    """Script entry point"""
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    parse_arguments()

    logging.basicConfig(
        level=shared.log_level,
        format='[%(asctime)s] [%(levelname)s] %(message)s')
    logging.info('Starting MiNode')

    logging.info('Data directory: %s', shared.data_directory)
    if not os.path.exists(shared.data_directory):
        try:
            os.makedirs(shared.data_directory)
        except Exception:
            logging.warning(
                'Error while creating data directory in: %s',
                shared.data_directory, exc_info=True)

    if shared.socks_proxy and shared.send_outgoing_connections:
        try:
            socks.PROXY_TYPES[shared.socks_proxy.scheme.upper()]
        except KeyError:
            logging.error('Unsupported proxy schema!')
            return

    if shared.tor:
        try:
            from . import tor  # pylint: disable=import-outside-toplevel
            if not tor.start_tor_service():
                logging.warning('The tor service has not started.')
                tor = None
        except ImportError:
            logging.info('Failed to import tor module.', exc_info=True)
            tor = None

        if not tor:
            try:
                socket.socket().bind(('127.0.0.1', 9050))
                return
            except (OSError, socket.error):
                pass
    elif shared.ip_enabled and not shared.trusted_peer:
        bootstrap_from_dns()

    shared.objects = sql.Inventory()

    if shared.i2p_enabled:
        # We are starting it before cleaning expired objects
        # so we can collect I2P destination objects
        start_i2p_listener()

    manager = Manager()
    manager.start()

    advertiser = Advertiser()
    advertiser.start()

    if shared.listen_for_connections:
        start_ip_listener()


if __name__ == '__main__':
    multiprocessing.set_start_method('spawn')
    main()
