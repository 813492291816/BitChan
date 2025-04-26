# -*- coding: utf-8 -*-
"""Common variables and structures, referred in different threads"""
import logging
import os
import queue
import threading

listening_port = 8444
listening_host = ''
send_outgoing_connections = True
listen_for_connections = True
data_directory = 'minode_data/'
source_directory = os.path.dirname(os.path.realpath(__file__))
trusted_peer = None
ip_enabled = True

log_level = logging.INFO

magic_bytes = b'\xe9\xbe\xb4\xd9'
protocol_version = 3
services = 3  # NODE_NETWORK, NODE_SSL
stream = 1
nonce = os.urandom(8)
user_agent = b'/MiNode:0.3.5/'
timeout = 600
header_length = 24
i2p_dest_obj_type = 0x493250
i2p_dest_obj_version = 1
onion_obj_type = 0x746f72
onion_obj_version = 3

socks_proxy = None
tor = False
onion_hostname = ''

i2p_enabled = False
i2p_transient = False
i2p_sam_host = '127.0.0.1'
i2p_sam_port = 7656
i2p_tunnel_length = 2
i2p_session_nick = b''
i2p_dest_pub = b''

nonce_trials_per_byte = 1000
payload_length_extra_bytes = 1000

shutting_down = False

vector_advertise_queue = queue.Queue()
address_advertise_queue = queue.Queue()

connections = set()
connections_lock = threading.Lock()

i2p_dialers = set()

hosts = set()

core_nodes = set()

node_pool = set()
unchecked_node_pool = set()
nonce_pool = {}

i2p_core_nodes = set()
i2p_node_pool = set()
i2p_unchecked_node_pool = set()

onion_pool = set()
onion_unchecked_pool = set()

outgoing_connections = 8
connection_limit = 250

objects = {}
