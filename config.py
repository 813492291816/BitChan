import logging
import os
from logging import handlers

VERSION_BITCHAN = "0.9.0"
VERSION_ALEMBIC = '000000000000'
VERSION_MIN_MSG = "0.9.0"

LOG_LEVEL = logging.INFO

#
# BitChan
#
THREADS_PER_PAGE = 15
ID_LENGTH = 9
LABEL_LENGTH = 25
CLEAR_INVENTORY_WAIT = 60 * 10  # 10 minutes
BM_TTL = 60 * 60 * 24 * 28  # 28 days
BM_PAYLOAD_MAX_SIZE = 348768
BM_REFRESH_PERIOD = 5
BANNER_MAX_WIDTH = 650
BANNER_MAX_HEIGHT = 400
DOWNLOAD_MAX_AUTO = 5000000
SEND_BEFORE_EXPIRE_DAYS = 20
UPLOAD_SIZE_TO_THREAD = 5000000
FILE_EXTENSIONS_AUDIO = ["wav", "mp3", "ogg"]
FILE_EXTENSIONS_IMAGE = ["jpg", "jpeg", "png", "gif", "webp"]
FILE_EXTENSIONS_VIDEO = ["mp4", "webm", "ogg"]
RESTRICTED_WORDS = ['bitchan', 'bltchan']
PASSPHRASE_MSG = """;!_:2H wCZA@aiuIN# YsJ_k3cG!..ch:>"3'&ca2h?*g PUN)AAI7P4.O%HP!9a$I@,Gn"""
PASSPHRASE_ZIP = """e}rs>!f_!ZqIQ1d9+>Tb!Ob0&}o;C=E|uBP.sPm%&7aaQU;Hm7Vl2A/L"ka^JV9iSUad<<"""
PASSPHRASE_STEG = """[J;-Ao2id-1M$;Q:.=`[q5n'/kD,=h_M'B[S-_A"SMI^HEKejZT&Au0~c41||:g9Rf2Ez8"""
BITCHAN_DEVELOPER_ADDRESS = "BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ"
BITCHAN_BUG_REPORT_ADDRESS = "BM-2cVzMZfiP9qQw5MiKHD8whxrqdCwqtvdyE"

INSTALL_DIR = "/usr/local/bitchan"
ALEMBIC_POST = os.path.join(INSTALL_DIR, 'post_alembic_versions')
DATABASE_BITCHAN = os.path.join(INSTALL_DIR, 'bitchan.db')
FILE_DIRECTORY = os.path.join(INSTALL_DIR, "downloaded_files")
LOG_DIRECTORY = os.path.join(INSTALL_DIR, "log")
LOG_FILE = os.path.join(LOG_DIRECTORY, "bitchan.log")
LOCKFILE_API = "/var/lock/bm_api.lock"
LOCKFILE_MSG_PROC = "/var/lock/bm_msg_proc.lock"

ADMIN_OPTIONS = [
    "delete_comment",
    "delete_post",
    "delete_thread",
    "ban_address",
    "modify_admin_addresses",
    "modify_user_addresses",
    "modify_restricted_addresses",
    "word_replace",
    "css",
    "banner_base64",
]

DICT_UPLOAD_SERVERS = {
    "anonfile": {
        "uri": None,
        "form_name": "Anonfiles.com (less secure, 100GB max)"
    },
    "bayfiles": {
        "uri": None,
        "form_name": "Bayfiles.com (less secure, 20GB max)"
    },
    "forumfiles": {
        "uri": "https://api.forumfiles.com",
        "form_name": "ForumFiles.com (less secure, 20GB max)"
    },
    "uplovd": {
        "uri": "https://api.uplovd.com",
        "form_name": "Uplovd.com (less secure, 20GB max)"
    }
}
UPLOAD_SERVERS_NAMES = [(k, v["form_name"]) for k, v in DICT_UPLOAD_SERVERS.items()]

DICT_PERMISSIONS = {
    "require_identity_to_post": "Require Identity to Post",
    "automatic_wipe": "Automatic Wipe"
}

DEFAULT_CHANS = [
    {
        "address": "BM-2cUmjx3XGuftJhHGXfoaA5TfyGpFFvLgzB",
        "access": "public",
        "type": "board",
        "label": "babby",
        "description": "Babby's First Board",
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

#
# BitMessage
#
messages_dat = "/usr/local/bitmessage/messages.dat"
keys_dat = "/usr/local/bitmessage/keys.dat"
host = "bitmessage"
port = 8445
username = "bitchan"
password = ""
with open(keys_dat) as f:
    for line in f:
        if "apipassword" in line:
            password = line.split("=")[1].strip()

#
# tor
#
TOR_PASS = "torpass1234"
TOR_PROXIES = {
    "http": "socks5://tor:9060",
    "https": "socks5://tor:9060"
}

#
# Misc.
#
if os.environ.get('DOCKER', False) == 'TRUE':
    DOCKER = True
else:
    DOCKER = False

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
    SECRET_KEY = os.urandom(32)
    DB_PATH = 'sqlite:///{}'.format(DATABASE_BITCHAN)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///{}'.format(DATABASE_BITCHAN)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
