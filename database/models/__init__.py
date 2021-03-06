import json
import logging

import config
from utils.general import set_clear_time_to_future
from .alembic import Alembic
from .chans import AddressBook
from .chans import AdminMessageStore
from .chans import Chan
from .chans import Command
from .chans import Identity
from .chans import Messages
from .chans import Threads
from .chans import UploadProgress
from .maintenance import DeletedMessages
from .maintenance import PostMessages
from .settings import Flags
from .settings import GlobalSettings
from .settings import UploadSites

logger = logging.getLogger('bitchan.db_models')


def populate_db():
    if not Alembic.query.count():
        Alembic().save()

    if not GlobalSettings.query.count():
        GlobalSettings().save()

    # Only for testing. TODO: remove for release
    # for each in UploadSites.query.all():
    #     each.delete()

    if not UploadSites.query.count():
        for domain, upload_info in config.DICT_UPLOAD_SERVERS.items():
            UploadSites(
                domain=domain,
                type=upload_info["type"],
                uri=upload_info["uri"],
                download_prefix=upload_info["download_prefix"],
                response=upload_info["response"],
                direct_dl_url=upload_info["direct_dl_url"],
                extra_curl_options=upload_info["extra_curl_options"],
                upload_word=upload_info["upload_word"],
                form_name=upload_info["form_name"],
            ).save()

    if not AddressBook.query.count():
        AddressBook(
            address=config.BITCHAN_DEVELOPER_ADDRESS,
            label="BitChan Developer"
        ).save()

    if not Chan.query.count():
        for each_chan in config.DEFAULT_CHANS:
            from utils.general import generate_passphrase
            passphrase = generate_passphrase(
                each_chan["access"],
                each_chan["type"],
                each_chan["label"],
                each_chan["description"],
                each_chan["restricted_addresses"],
                each_chan["primary_addresses"],
                each_chan["secondary_addresses"],
                each_chan["tertiary_addresses"],
                each_chan["rules"],
                each_chan["extra_string"]
            )

            if each_chan["rules"]:
                each_chan["rules"] = set_clear_time_to_future(each_chan["rules"])

            Chan(
                access=each_chan["access"],
                type=each_chan["type"],
                address=each_chan["address"],
                passphrase=passphrase,
                label=each_chan["label"],
                description=each_chan["description"],
                restricted_addresses=json.dumps(each_chan["restricted_addresses"]),
                primary_addresses=json.dumps(each_chan["primary_addresses"]),
                secondary_addresses=json.dumps(each_chan["secondary_addresses"]),
                tertiary_addresses=json.dumps(each_chan["tertiary_addresses"]),
                rules=json.dumps(each_chan["rules"]),
                pgp_passphrase_msg=config.PGP_PASSPHRASE_MSG,
                pgp_passphrase_attach=config.PGP_PASSPHRASE_ATTACH,
                pgp_passphrase_steg=config.PGP_PASSPHRASE_STEG
            ).save()
