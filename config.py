import logging
import os
from logging import handlers

VERSION_BITCHAN = "0.11.1"
VERSION_ALEMBIC = '000000000000'
VERSION_MIN_MSG = "0.11.0"

LOG_LEVEL = logging.INFO

#
# BitChan
#
API_TIMEOUT = 15
THREADS_PER_PAGE = 15
ID_LENGTH = 9
LABEL_LENGTH = 25
DESCRIPTION_LENGTH = 128
LONG_DESCRIPTION_LENGTH = 1000
CLEAR_INVENTORY_WAIT = 60 * 5  # 5 minutes
BM_TTL = 60 * 60 * 24 * 28  # 28 days
BM_PAYLOAD_MAX_SIZE = 2 ** 18 - 500  # 261,644
BM_REFRESH_PERIOD = 5
BM_SYNC_CHECK_PERIOD = 10
BM_UNREAD_CHECK_PERIOD = 120
BANNER_MAX_WIDTH = 650
BANNER_MAX_HEIGHT = 400
SPOILER_MAX_WIDTH = 250
SPOILER_MAX_HEIGHT = 250
DOWNLOAD_ATTEMPTS = 5
MAX_FILE_EXT_LENGTH = 8
SEND_BEFORE_EXPIRE_DAYS = 20
UPLOAD_SIZE_TO_THREAD = 5000000
FLAG_MAX_WIDTH = 25
FLAG_MAX_HEIGHT = 15
FLAG_MAX_SIZE = 3500
MAX_SUBJECT_COMMENT = 246250
THREAD_MAX_LINES = 18
THREAD_MAX_CHARACTERS = 4000
THREAD_MAX_HEIGHT_EM = 45
BOARD_MAX_LINES = 12
BOARD_MAX_CHARACTERS = 6000
PGP_PASSPHRASE_LENGTH = 250
PASSPHRASE_EXTRA_STRING_LENGTH = 250
PASSPHRASE_ADDRESSES_LENGTH = 1000
WIPE_INTERVAL_MAX = 15778800000
WIPE_START_MAX = 33134749200
FILE_ATTACHMENTS_MAX = 4
FILE_EXTENSIONS_AUDIO = ["wav", "mp3", "ogg"]
FILE_EXTENSIONS_IMAGE = ["jpg", "jpeg", "png", "gif", "webp"]
FILE_EXTENSIONS_VIDEO = ["mp4", "webm", "ogg"]
RESTRICTED_WORDS = ['bitchan', 'bltchan']
PGP_PASSPHRASE_MSG = """;!_:2H wCsA@aiuIk# YsJ_k3cG!..ch:>"3'&ca2h?*g PUN)AAI7P4.O%HP!9a$I@,Gn"""
PGP_PASSPHRASE_ATTACH = """e}rs>!f_!ZqIQ1d9+>Tb!Ob0&}o;C=E|uBP.sPm%&7aaQU;H*7Vl2A/L"9a^JV9iSUad<<"""
PGP_PASSPHRASE_STEG = """[J;-Ao2id-1M$;Q:.=`[q5n'/QD,=h_M'B[S-_A"SMI^HEKejZT&Au0~c41||:g9Rf2Ez8"""
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
    "spoiler_base64",
    "long_description"
]

DICT_UPLOAD_SERVERS = {
    "pomf.cat": {
        "type": "curl",
        "uri": "https://pomf.cat/upload.php",
        "download_prefix": "https://a.pomf.cat",
        "response": "JSON",
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "form_name": "pomf.cat (75 MB)"
    },
    "youdieifyou.work": {
        "type": "curl",
        "uri": "https://youdieifyou.work/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "form_name": "youdieifyou.work (128 MB)"
    },
    "uguu.se": {
        "type": "curl",
        "uri": "https://uguu.se/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "form_name": "uguu.se (100 MB, 24h expire)"
    },
    "femto.pw": {
        "type": "curl",
        "uri": "https://v2.femto.pw/upload",
        "download_prefix": "https://femto.pw",
        "response": "JSON",
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "upload",
        "form_name": "v2.femto.pw (8 GB)"
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
        "uri": None,
        "download_prefix": None,
        "response": None,
        "direct_dl_url": False,
        "extra_curl_options": None,
        "upload_word": None,
        "form_name": "anonfiles.com (100 GB)"
    },
    "bayfiles": {
        "type": "anonfile",
        "uri": None,
        "download_prefix": None,
        "response": None,
        "direct_dl_url": False,
        "extra_curl_options": None,
        "upload_word": None,
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

THEMES_DARK = ["Dark"]
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
# Bitmessage
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
