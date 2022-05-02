import json
import logging
import os
from datetime import timedelta
from logging import handlers

logger = logging.getLogger('bitchan.config')

VERSION_BITCHAN = "1.1.0"
VERSION_ALEMBIC = '000000000063'
VERSION_MSG = "1.0.0"
VERSION_MIN_MSG = "1.0.0"

LOG_LEVEL = logging.INFO

#
# Bitmessage
#
BM_HOST = "172.28.1.3"
BM_PORT = 8445
BM_USERNAME = "bitchan"
BM_PASSWORD = ""
messages_dat = "/usr/local/bitmessage/messages.dat"
keys_dat = "/usr/local/bitmessage/keys.dat"
with open(keys_dat) as f:
    for line in f:
        if "apipassword" in line:
            BM_PASSWORD = line.split("=")[1].strip()

#
# tor
#
TOR_HOST = "172.28.1.2"
TOR_SOCKS_PORT = 9060
TOR_CONTROL_PORT = 9061
TOR_PASS = "torpass1234"  # also change tor password in docker-compose.yml
TOR_PROXIES = {
    "http": "socks5://{host}:{port}".format(host=TOR_HOST, port=TOR_SOCKS_PORT),
    "https": "socks5://{host}:{port}".format(host=TOR_HOST, port=TOR_SOCKS_PORT)
}

#
# i2p
#
I2P_HOST = "172.28.1.6"
I2P_SOCKS_PORT = 4444
I2P_PROXIES = {
    "http": "http://{host}:{port}".format(host=I2P_HOST, port=I2P_SOCKS_PORT),
    "https": "http://{host}:{port}".format(host=I2P_HOST, port=I2P_SOCKS_PORT)
}

#
# BitChan
#
INSTALL_DIR = "/usr/local/bitchan"
REFRESH_BOARD_INFO = 20
REFRESH_CHECK_DOWNLOAD = 5
REFRESH_ADDRESS_MSG = 20
REFRESH_CHECK_SYNC = 30
REFRESH_THREAD_QUEUE = 5
REFRESH_CHECK_LISTS = (60 * 60 * 6)  # 6 hours
REFRESH_CHECK_CMDS = (60 * 60 * 6)  # 6 hours
REFRESH_CLEAR_PROGRESS = 600
REFRESH_EXPIRES_TIME = (60 * 10)  # 10 minutes
REFRESH_DELETE_SENT = (60 * 10)  # 10 minutes
REFRESH_REMOVE_DEL = (60 * 60 * 24)  # 1 day
REFRESH_UNREAD_COUNT = 120
SESSION_TIMEOUT_DAYS = 30
MAX_PROC_THREADS = 5
API_CHECK_FREQ = 15
API_TIMEOUT = 15
API_PAUSE = 0.3
API_LOCK_TIMEOUT = 120
BM_WAIT_DELAY = 120
BM_TTL = 60 * 60 * 24 * 28  # 28 days
BM_PAYLOAD_MAX_SIZE = 2 ** 18 - 500  # 261,644
CLEAR_INVENTORY_WAIT = 60 * 10  # 10 minutes
LIST_ADD_WAIT_TO_SEND_SEC = 60 * 5  # 5 minutes
ID_LENGTH = 9
LABEL_LENGTH = 25
DESCRIPTION_LENGTH = 128
LONG_DESCRIPTION_LENGTH = 1000
BANNER_MAX_WIDTH = 650
BANNER_MAX_HEIGHT = 400
SPOILER_MAX_WIDTH = 250
SPOILER_MAX_HEIGHT = 250
DOWNLOAD_ATTEMPTS = 5
MAX_FILE_EXT_LENGTH = 8
SEND_BEFORE_EXPIRE_DAYS = 20
UPLOAD_SIZE_TO_THREAD = 5 * 1024 * 1024  # 5 MB
UPLOAD_FRAG_AMT = 3
UPLOAD_FRAG_START_BYTES = 100
UPLOAD_FRAG_END_BYTES = 100
UPLOAD_FRAG_MIN_BYTES = 50
UPLOAD_FRAG_MAX_BYTES = 500
FLAG_MAX_WIDTH = 25
FLAG_MAX_HEIGHT = 15
FLAG_MAX_SIZE = 3500
MAX_SUBJECT_COMMENT = 246250
THREAD_MAX_HEIGHT_EM = 45
BOARD_MAX_LINES = 12
BOARD_MAX_CHARACTERS = 6000
PGP_PASSPHRASE_LENGTH = 250
PASSPHRASE_EXTRA_STRING_LENGTH = 250
PASSPHRASE_ADDRESSES_LENGTH = 1000
WIPE_INTERVAL_MAX = 15778800000
WIPE_START_MAX = 33134749200
INDEX_CARDS_OP_TRUNCATE_CHARS = 110
INDEX_CARDS_REPLY_TRUNCATE_CHARS = 75
FILE_ATTACHMENTS_MAX = 4
FILE_EXTENSIONS_AUDIO = ["m4a", "opus", "wav", "mp3", "ogg"]
FILE_EXTENSIONS_IMAGE = ["jpg", "jpeg", "png", "gif", "webp", "svg"]
FILE_EXTENSIONS_VIDEO = ["mp4", "webm", "ogg"]
RESTRICTED_WORDS = ['bitchan', 'bltchan']
PGP_PASSPHRASE_MSG = """;!_:2H wCsA@aiuIk# YsJ_k3cG!..ch:>"3'&ca2h?*g PUN)AAI7P4.O%HP!9a$I@,Gn"""
PGP_PASSPHRASE_ATTACH = """e}rs>!f_!ZqIQ1d9+>Tb!Ob0&}o;C=E|uBP.sPm%&7aaQU;H*7Vl2A/L"9a^JV9iSUad<<"""
PGP_PASSPHRASE_STEG = """[J;-Ao2id-1M$;Q:.=`[q5n'/QD,=h_M'B[S-_A"SMI^HEKejZT&Au0~c41||:g9Rf2Ez8"""
BITCHAN_DEVELOPER_ADDRESS = "BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ"
BITCHAN_BUG_REPORT_ADDRESS = "BM-2cVzMZfiP9qQw5MiKHD8whxrqdCwqtvdyE"

ALEMBIC_POST = os.path.join(INSTALL_DIR, 'post_alembic_versions')
DATABASE_BITCHAN = os.path.join(INSTALL_DIR, 'bitchan.db')
FILE_DIRECTORY = os.path.join(INSTALL_DIR, "downloaded_files")
LOG_DIRECTORY = os.path.join(INSTALL_DIR, "log")
LOG_FILE = os.path.join(LOG_DIRECTORY, "bitchan.log")

LOCKFILE_ADMIN_CMD = "/var/lock/bc_admin_cmd.lock"
LOCKFILE_API = "/var/lock/bm_api.lock"
LOCKFILE_MSG_PROC = "/var/lock/bm_msg_proc.lock"
LOCKFILE_STORE_POST = "/var/lock/store_post.lock"
LOCKFILE_ENDPOINT_COUNTER = "/var/lock/endpoint_count.lock"

ADMIN_OPTIONS = [
    "delete_comment",
    "delete_post",
    "delete_thread",
    "board_ban_silent",
    "board_ban_public",
    "modify_admin_addresses",
    "modify_user_addresses",
    "modify_restricted_addresses",
    "word_replace",
    "css",
    "banner_base64",
    "spoiler_base64",
    "long_description",
]

GAMES = {
    "chess": "Chess",
    "tic_tac_toe": "Tic Tac Toe"
}

DICT_UPLOAD_SERVERS = {
    "pomf.cat": {
        "type": "curl",
        "subtype": None,
        "uri": "https://pomf.cat/upload.php",
        "download_prefix": "https://a.pomf.cat",
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "pomf.cat (75 MB)"
    },
    "lyrhscn2hfe6mjn7jo3titioitfzcy7x23hhkksydin6ildsgxiq.b32.i2p": {
        "type": "curl",
        "subtype": "simple_upload",
        "uri": 'http://lyrhscn2hfe6mjn7jo3titioitfzcy7x23hhkksydin6ildsgxiq.b32.i2p/upload',
        "download_prefix": None,
        "response": "JSON",
        "json_key": 'direct_url',
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": None,
        "http_headers": '["Accept: application/json"]',
        "proxy_type": "i2p",
        "replace_download_domain": None,
        "form_name": "bunkerfiles.i2p (? MB, 12h expire)"
    },
    "apo53zid3xe7rewxjw7whdym2rmyowsj7jeoiwrl5zlmf7oqrxwq.b32.i2p": {
        "type": "curl",
        "subtype": "simple_upload",
        "uri": 'http://apo53zid3xe7rewxjw7whdym2rmyowsj7jeoiwrl5zlmf7oqrxwq.b32.i2p',
        "download_prefix": None,
        "response": "str_url",
        "json_key": 'direct_url',
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": None,
        "http_headers": None,
        "proxy_type": "i2p",
        "replace_download_domain": '["0xff.i2p", "apo53zid3xe7rewxjw7whdym2rmyowsj7jeoiwrl5zlmf7oqrxwq.b32.i2p"]',
        "form_name": "0xff.i2p (128 MB, 15d - 200d expire)"
    },
    "uguu.se": {
        "type": "curl",
        "subtype": None,
        "uri": "https://uguu.se/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "uguu.se (100 MB, 24h expire)"
    },
    "femto.pw": {
        "type": "curl",
        "subtype": None,
        "uri": "https://v2.femto.pw/upload",
        "download_prefix": "https://femto.pw",
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "upload",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "v2.femto.pw (8 GB)"
    },
    "youdieifyou.work": {
        "type": "curl",
        "subtype": None,
        "uri": "https://youdieifyou.work/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "youdieifyou.work (128 MB)"
    },
    # "catbox.moe": {  # Some tor IPs are blocked, don't use. Here for posterity.
    #     "type": "curl",
    #     "uri": "https://catbox.moe/user/api.php",
    #     "download_prefix": None,
    #     "response": "str_url",
    #     "direct_dl_url": True,
    #     "extra_curl_options": "-F reqtype=fileupload",
    #     "upload_word": "fileToUpload",
    #     "form_name": "catbox.moe (200 MB)"
    # },
    "anonfile": {
        "type": "anonfile",
        "subtype": None,
        "uri": None,
        "download_prefix": None,
        "response": None,
        "json_key": None,
        "direct_dl_url": False,
        "extra_curl_options": None,
        "upload_word": None,
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "anonfiles.com (100 GB)"
    },
    "bayfiles": {
        "type": "anonfile",
        "subtype": None,
        "uri": None,
        "download_prefix": None,
        "response": None,
        "json_key": None,
        "direct_dl_url": False,
        "extra_curl_options": None,
        "upload_word": None,
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "bayfiles.com (20 GB)"
    }
}
UPLOAD_BANNED_EXT = ["exe", "scr", "cpl", "doc", "jar", "zip", "tar"]
UPLOAD_ENCRYPTION_CIPHERS = [
    ("XChaCha20-Poly1305,32", "XChaCha20-Poly1305 (256-bit key)"),
    ("AES-GCM,32", "AES-GCM (256-bit key)"),
    ("AES-GCM,24", "AES-GCM (192-bit key)"),
    ("AES-GCM,16", "AES-GCM (128-bit key)"),
    ("NONE,999", "No Encryption")
]

DICT_PERMISSIONS = {
    "require_identity_to_post": "Require Identity to Post",
    "automatic_wipe": "Automatic Wipe",
    "allow_list_pgp_metadata": "Allow Lists to Store PGP Passphrases"
}

DEFAULT_CHANS = [
    {
        "address": "BM-2cXxMxqBBEMAdZhL86K4i2W7cUBj72EVCj",
        "access": "public",
        "type": "board",
        "label": "babby",
        "description": "Babby's First Board",
        "restricted_addresses": [
            "BM-2cUYu7r41Bbnox4P8gEVtdnZGLnisgG7Yu",
            "BM-2cVZdtgUe7uq7LbWx12W2btJybAphF3VxG",
            "BM-2cTjxB1RMaPV64emmF63w1J9RQYDVz26vP"
        ],
        "primary_addresses": [],
        "secondary_addresses": [],
        "tertiary_addresses": [],
        "rules": {
            "automatic_wipe": {
                "wipe_epoch": 1604357919,
                "interval_seconds": 60 * 60 * 24 * 30  # 30 days
            }
        },
        "extra_string": ""
    },
    {
        "address": "BM-2cTjxB1RMaPV64emmF63w1J9RQYDVz26vP",
        "access": "public",
        "type": "list",
        "label": "bablist",
        "description": "Babby's First List",
        "restricted_addresses": [],
        "primary_addresses": [],
        "secondary_addresses": [],
        "tertiary_addresses": [],
        "rules": {
            "automatic_wipe": {
                "wipe_epoch": 1604357919,
                "interval_seconds": 60 * 60 * 24 * 30  # 30 days
            }
        },
        "extra_string": ""
    },
    {
        "address": "BM-2cUYu7r41Bbnox4P8gEVtdnZGLnisgG7Yu",
        "access": "private",
        "type": "list",
        "label": "bitchan",
        "description": "BitChan",
        "restricted_addresses": [],
        "primary_addresses": [BITCHAN_DEVELOPER_ADDRESS],
        "secondary_addresses": [],
        "tertiary_addresses": [],
        "rules": {},
        "extra_string": ""
    },
    {
        "address": "BM-2cVZdtgUe7uq7LbWx12W2btJybAphF3VxG",
        "access": "private",
        "type": "board",
        "label": "bitchan-dev",
        "description": "BitChan Development",
        "restricted_addresses": [],
        "primary_addresses": [BITCHAN_DEVELOPER_ADDRESS],
        "secondary_addresses": [],
        "tertiary_addresses": [],
        "rules": {},
        "extra_string": ""
    }
]

THEMES_DARK = ["Dark", "Console"]
THEMES_LIGHT = ["Classic", "Frosty"]

#
# Mailbox
#
MSGS_PER_PAGE = [
    (5, "5 per page"),
    (15, "15 per page"),
    (25, "25 per page"),
    (50, "50 per page"),
    (10000, "All messages")
]

#
# Misc.
#
DOCKER = os.environ.get('DOCKER', False) == 'TRUE'

if DOCKER:
    PYRO_URI = 'PYRO:bitchan.pyro_server@bitchan_daemon:9099'
else:
    PYRO_URI = 'PYRO:bitchan.pyro_server@127.0.0.1:9099'

PATH_RUN = '/var/run'
PATH_DAEMON_PID = os.path.join(PATH_RUN, 'bitchan.pid')

directories = [LOG_DIRECTORY, FILE_DIRECTORY]
for each_directory in directories:
    if not os.path.exists(each_directory):
        try:
            os.makedirs(each_directory)
        except Exception:
            pass

logging.basicConfig(
    level=LOG_LEVEL,
    format="[%(asctime)s] %(levelname)s/%(name)s: %(message)s",
    handlers=[
        handlers.RotatingFileHandler(
            LOG_FILE, mode='a', maxBytes=5*1024*1024,
            backupCount=1, encoding=None, delay=False
        ),
        logging.StreamHandler()
    ]
)


class ProdConfig(object):
    key = None
    try:
        if os.path.exists('/usr/local/bitchan/flask_secret_key'):
            with open('/usr/local/bitchan/flask_secret_key', 'r') as r:
                contents = str(r.read())
                if contents:
                    key = contents
        if not key:
            key = str(os.urandom(32))
            with open('/usr/local/bitchan/flask_secret_key', 'w') as w:
                w.write(key)
    except:
        key = str(os.urandom(32))

    SECRET_KEY = key
    SESSION_TYPE = "filesystem"
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)

    CAPTCHA_ENABLE = True
    CAPTCHA_LENGTH = 5
    CAPTCHA_WIDTH = 160
    CAPTCHA_HEIGHT = 50
    CAPTCHA_FONTS = ['/home/bitchan/static/fonts/carbontype.ttf']
    DB_PATH = 'sqlite:///{}'.format(DATABASE_BITCHAN)

    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(DATABASE_BITCHAN)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
