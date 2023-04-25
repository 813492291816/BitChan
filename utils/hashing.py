import json
import logging

import config
from database.models import Messages
from database.utils import session_scope
from utils.download import process_attachments

logger = logging.getLogger('bitchan.hashing')

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN


def regen_all_hashes():
    list_ids = []
    with session_scope(DB_PATH) as new_session:
        for each_message in new_session.query(Messages).all():
            list_ids.append(each_message.message_id)

    for message_id in list_ids:
        try:
            extract_path = f"{config.FILE_DIRECTORY}/{message_id}"
            errors_files, media_info, message_steg = process_attachments(
                message_id, extract_path, progress=False)
            with session_scope(DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    message.media_info = json.dumps(media_info)
                    new_session.commit()
        except:
            pass
