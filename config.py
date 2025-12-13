import logging
import os

from cachelib.file import FileSystemCache

logger = logging.getLogger('bitchan.config')

DOCKER = os.environ.get('DOCKER', False) == 'TRUE'

VERSION_BITCHAN = "1.4.2"
VERSION_ALEMBIC = '000000000142'
VERSION_MSG = "1.3.0"
VERSION_MIN_MSG = "1.3.0"

LOG_LEVEL = logging.INFO
# LOG_LEVEL = logging.DEBUG

# Kiosk Recovery User
# Only temporarily enable this to log into the kiosk.
# Used when kiosk mode is enabled and you don't have valid credentials to log in.
# The default password DEFAULT_PASSWORD_CHANGE_ME will not work. Change it.
# Save this file and restart the front end for the changes to take effect.
# Remember to disable this by commenting it out after you add an admin user on the User Management page.
# KIOSK_RECOVERY_USER_PASSWORD = "DEFAULT_PASSWORD_CHANGE_ME"

#
# Bitmessage
#

if DOCKER:
    BM_HOST = "172.28.1.3"
    BM_PATH = "/usr/local/bitmessage"
else:
    BM_HOST = "127.0.0.1"
    BM_PATH = "/usr/local/bitchan/bitmessage"

BM_MESSAGES_DAT = os.path.join(BM_PATH, "messages.dat")
BM_KNOWNNODES_DAT = os.path.join(BM_PATH, "knownnodes.dat")
BM_KEYS_DAT = os.path.join(BM_PATH, "keys.dat")
BM_PORT = 8445
BM_USERNAME = ""
BM_PASSWORD = ""

if os.path.exists(BM_KEYS_DAT):
    with open(BM_KEYS_DAT) as f:
        for line in f:
            if "apiusername" in line:
                BM_USERNAME = line.split("=")[1].strip()

if os.path.exists(BM_KEYS_DAT):
    with open(BM_KEYS_DAT) as f:
        for line in f:
            if "apipassword" in line:
                BM_PASSWORD = line.split("=")[1].strip()

if DOCKER:
    MINODE_ARGS_PATH = "/home/minode/minode_data/run_args"
else:
    MINODE_ARGS_PATH = "/usr/local/bitchan/minode/minode_data/run_args"

if DOCKER:
    GPG_DIR = "/usr/local/gnupg"
else:
    GPG_DIR = "/usr/local/bitchan/gnupg"

#
# tor
#

if DOCKER:
    TOR_HOST = "172.28.1.2"
    TOR_PATH = "/usr/local/tor"
else:
    TOR_HOST = "127.0.0.1"
    TOR_PATH = "/usr/local/bitchan/tor"

TORRC = f"{TOR_PATH}/torrc"
TOR_HS_BM = f"{TOR_PATH}/bm"
TOR_HS_RAND = f"{TOR_PATH}/rand"
TOR_HS_CUS = f"{TOR_PATH}/cus"
TOR_CONTROL_PASS = f"{TOR_PATH}/torpass"

TOR_POW_ENABLE = 1
TOR_POW_QUEUE_RATE = 3
TOR_POW_QUEUE_BURST = 10

TOR_PASS = ""
if os.path.exists(TOR_CONTROL_PASS):
    with open(TOR_CONTROL_PASS) as f:
        TOR_PASS = f.read().strip()

TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_PROXIES = {
    "http": "socks5://{host}:{port}".format(host=TOR_HOST, port=TOR_SOCKS_PORT),
    "https": "socks5://{host}:{port}".format(host=TOR_HOST, port=TOR_SOCKS_PORT)
}

#
# i2pd
#

if DOCKER:
    I2P_HOST = "172.28.1.6"
    I2PD_PATH = "/home/i2pd/data"
    I2PD_DATA_PATH = "/home/i2pd/data"
else:
    I2P_HOST = "127.0.0.1"
    I2PD_PATH = "/usr/local/bitchan/i2pd"
    I2PD_DATA_PATH = "/usr/local/bitchan/i2pd_data"

I2P_WEBUI_PORT = 7070
I2P_HTTP_PORT = 4444
I2P_PROXIES = {
    "http": "http://{host}:{port}".format(host=I2P_HOST, port=I2P_HTTP_PORT),
    "https": "http://{host}:{port}".format(host=I2P_HOST, port=I2P_HTTP_PORT)
}

#
# qbittorrent
#

if DOCKER:
    QBITTORRENT_HOST = "172.28.1.8"
else:
    QBITTORRENT_HOST = "127.0.0.1"

QBITTORRENT_PORT = 8080

#
# MySQL
#

if DOCKER:
    DB_HOST = "172.28.1.7"
else:
    DB_HOST = "127.0.0.1"

DB_NAME = 'bitchan_db'
DB_PW = 'Bitchandbpw'
DB_PATH = f'mysql+pymysql://root:{DB_PW}@{DB_HOST}/{DB_NAME}'

#
# BitChan
#

INSTALL_DIR = "/usr/local/bitchan"

if DOCKER:
    DAEMON_BIND_IP = "172.28.1.5"
    CODE_DIR = "/home/bitchan"
else:
    DAEMON_BIND_IP = "127.0.0.1"
    CODE_DIR = "/usr/local/bitchan/BitChan"

BITCHAN_DIR = os.path.abspath(
    os.path.dirname(os.path.realpath(__file__)))
REFRESH_BOARD_INFO = 20
REFRESH_CHECK_DOWNLOAD = 5
REFRESH_MSGS = 20
REFRESH_ADDRESSES = 60
REFRESH_STATS = 90
REFRESH_CHECK_SYNC = 30
REFRESH_THREAD_QUEUE = 5
REFRESH_CHECK_LISTS = (60 * 60 * 6)  # 6 hours
REFRESH_CHECK_CMDS = (60 * 60 * 6)  # 6 hours
REFRESH_CLEAR_PROGRESS = 600
REFRESH_EXPIRES_TIME = (60 * 10)  # 10 minutes
REFRESH_DELETE_SENT = (60 * 10)  # 10 minutes
REFRESH_REMOVE_DEL = (60 * 60 * 24)  # 1 day
REFRESH_UNREAD_COUNT = 120
REFRESH_WIPE = 120
SESSION_TIMEOUT_DAYS = 31
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
OP_RESEND_JSON_OBJ_SEC = 60 * 60 * 24 * 20  # 20 days
ID_LENGTH = 9
LABEL_LENGTH = 25
DESCRIPTION_LENGTH = 128
LONG_DESCRIPTION_LENGTH = 1000
BANNER_MAX_WIDTH = 1200
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
FILE_EXTENSIONS_IMAGE = ["apng", "avif", "gif", "jpg", "jpeg", "png", "svg", "webp"]
FILE_EXTENSIONS_VIDEO = ["mp4", "webm", "ogg"]
RESTRICTED_WORDS = ['bitchan', 'bltchan']
PGP_PASSPHRASE_MSG = """;!_:2H wCsA@aiuIk# YsJ_k3cG!..ch:>"3'&ca2h?*g PUN)AAI7P4.O%HP!9a$I@,Gn"""
PGP_PASSPHRASE_ATTACH = """e}rs>!f_!ZqIQ1d9+>Tb!Ob0&}o;C=E|uBP.sPm%&7aaQU;H*7Vl2A/L"9a^JV9iSUad<<"""
PGP_PASSPHRASE_STEG = """[J;-Ao2id-1M$;Q:.=`[q5n'/QD,=h_M'B[S-_A"SMI^HEKejZT&Au0~c41||:g9Rf2Ez8"""
BITCHAN_DEVELOPER_ADDRESS = "BM-2cWyqGJHrwCPLtaRvs3f67xsnj8NmPvRWZ"
BITCHAN_BUG_REPORT_ADDRESS = "BM-2cVzMZfiP9qQw5MiKHD8whxrqdCwqtvdyE"

ALEMBIC_POST = os.path.join(INSTALL_DIR, 'post_alembic_versions')
FILE_DIRECTORY = os.path.join(INSTALL_DIR, "downloaded_files")
FILE_DIRECTORY_HASHED = os.path.join(INSTALL_DIR, "downloaded_files_hashed")
LOG_DIRECTORY = os.path.join(INSTALL_DIR, "log")
LOG_BACKEND_FILE = os.path.join(LOG_DIRECTORY, "bitchan_backend.log")
LOG_FRONTEND_FILE = os.path.join(LOG_DIRECTORY, "bitchan_frontend.log")
BAN_THUMB_DIRECTORY = os.path.join(INSTALL_DIR, "banned_thumbs")

LOCKFILE_ADMIN_CMD = "/var/lock/bc_admin_cmd.lock"
LOCKFILE_API = "/var/lock/bm_api.lock"
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
    "long_description",
]

GAMES = {
    "chess": "Chess",
    "tic_tac_toe": "Tic Tac Toe"
}

DICT_UPLOAD_SERVERS = {
    "desu.si": {
        "type": "curl",
        "subtype": None,
        "uri": "https://desu.si/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "desu.si (5 GB, 24h expire)"
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
    "pomf.wtf": {
        "type": "curl",
        "subtype": None,
        "uri": "https://pomf.wtf/upload.php",
        "download_prefix": None,
        "response": "JSON",
        "json_key": None,
        "direct_dl_url": True,
        "extra_curl_options": None,
        "upload_word": "files[]",
        "http_headers": None,
        "proxy_type": "tor",
        "replace_download_domain": None,
        "form_name": "pomf.wtf (5 GB, ?h expire)"
    },
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

    # No longer exist, used for reference to settings

    # "catbox.moe": {  # Some tor IPs are blocked
    #     "type": "curl",
    #     "uri": "https://catbox.moe/user/api.php",
    #     "download_prefix": None,
    #     "response": "str_url",
    #     "direct_dl_url": True,
    #     "extra_curl_options": "-F reqtype=fileupload",
    #     "upload_word": "fileToUpload",
    #     "form_name": "catbox.moe (200 MB)"
    # },
    # "femto.pw": {
    #     "type": "curl",
    #     "subtype": None,
    #     "uri": "https://v2.femto.pw/upload",
    #     "download_prefix": "https://femto.pw",
    #     "response": "JSON",
    #     "json_key": None,
    #     "direct_dl_url": True,
    #     "extra_curl_options": None,
    #     "upload_word": "upload",
    #     "http_headers": None,
    #     "proxy_type": "tor",
    #     "replace_download_domain": None,
    #     "form_name": "v2.femto.pw (8 GB)"
    # },
    # "lyrhscn2hfe6mjn7jo3titioitfzcy7x23hhkksydin6ildsgxiq.b32.i2p": {
    #     "type": "curl",
    #     "subtype": "simple_upload",
    #     "uri": 'http://lyrhscn2hfe6mjn7jo3titioitfzcy7x23hhkksydin6ildsgxiq.b32.i2p/upload',
    #     "download_prefix": None,
    #     "response": "JSON",
    #     "json_key": 'direct_url',
    #     "direct_dl_url": True,
    #     "extra_curl_options": None,
    #     "upload_word": None,
    #     "http_headers": '["Accept: application/json"]',
    #     "proxy_type": "i2p",
    #     "replace_download_domain": None,
    #     "form_name": "bunkerfiles.i2p (? MB, 12h expire)"
    # },
    # "youdieifyou.work": {
    #     "type": "curl",
    #     "subtype": None,
    #     "uri": "https://youdieifyou.work/upload.php",
    #     "download_prefix": None,
    #     "response": "JSON",
    #     "json_key": None,
    #     "direct_dl_url": True,
    #     "extra_curl_options": None,
    #     "upload_word": "files[]",
    #     "http_headers": None,
    #     "proxy_type": "tor",
    #     "replace_download_domain": None,
    #     "form_name": "youdieifyou.work (128 MB)"
    # },

}
UPLOAD_BANNED_EXT = ["exe", "scr", "cpl", "doc", "jar", "zip", "tar"]
UPLOAD_ENCRYPTION_CIPHERS = [
    ("XChaCha20-Poly1305,32", "XChaCha20-Poly1305 (256-bit key)"),
    ("AES-GCM,32", "AES-GCM (256-bit key)"),
    ("AES-GCM,24", "AES-GCM (192-bit key)"),
    ("AES-GCM,16", "AES-GCM (128-bit key)"),
    ("NONE,999", "No Encryption")
]

DICT_PERMISSIONS = {  # Board Rules
    "require_attachment_op": "Require Attachment for OP",
    "require_attachment": "Require Attachments for All Posts",
    "require_pow_to_post": "Require Proof of Work (POW) to Post",
    "require_identity_to_post": "Require Identity to Post",
    "restrict_thread_creation": "Restrict Thread Creation to Owners, Admins, and Thread Creation Users",
    "automatic_wipe": "Automatic Wipe",
    "allow_list_pgp_metadata": "Allow Lists to Store PGP Passphrases",
    "disallow_attachments": "Disallow Post Attachments"
}

DICT_THREAD_RULES = {  # Thread Rules
    "sort_replies_by_pow": "Sort Replies by POW",
    "require_pow_to_reply": "Require Proof of Work (POW) to Reply"
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

if DOCKER:
    PYRO_URI = 'PYRO:bitchan.pyro_server@bitchan_daemon:9099'
else:
    PYRO_URI = 'PYRO:bitchan.pyro_server@127.0.0.1:9099'

PATH_RUN = '/run'
PATH_DAEMON_PID = os.path.join(PATH_RUN, 'bitchan.pid')

directories = [LOG_DIRECTORY, FILE_DIRECTORY]
for each_directory in directories:
    if not os.path.exists(each_directory):
        try:
            os.makedirs(each_directory)
        except Exception:
            pass


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
    SESSION_TYPE = "cachelib"
    SESSION_CACHELIB = FileSystemCache(threshold=50000, cache_dir="/sessions")
    WTF_CSRF_TIME_LIMIT = 60*60*24 * 2  # expire in 2 days
    TEMPLATES_AUTO_RELOAD = True

    CAPTCHA_ENABLE = True
    CAPTCHA_LENGTH = 5
    CAPTCHA_WIDTH = 160
    CAPTCHA_HEIGHT = 50
    if DOCKER:
        CAPTCHA_FONTS = ['/home/bitchan/static/fonts/carbontype.ttf']
    else:
        CAPTCHA_FONTS = ['/usr/local/bitchan/BitChan/static/fonts/carbontype.ttf']

    SQLALCHEMY_DATABASE_URI = DB_PATH
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'max_overflow': 40
    }
