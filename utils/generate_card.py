import logging

import config
from bitchan_client import DaemonCom
from database.models import Messages
from database.utils import session_scope
from utils.generate_popup import generate_popup_post_html
from utils.generate_popup import generate_popup_post_body_file_info
from utils.generate_popup import generate_popup_post_header

daemon_com = DaemonCom()
logger = logging.getLogger("bitchan.generate_card")


def get_card_link_html(message, card_text=None, external_thread=False):
    if not message:
        msg = "Could not find message"
        logger.error(msg)
        return msg

    ret_str = ''

    try:
        ret_str += '<a class="reply-tooltip link">{lstr}' \
                   '<div class="reply-main">'.format(
            ch=message.thread.chan.address,
            th=message.thread.thread_hash,
            pid=message.post_id,
            lstr=card_text)

        if external_thread:
            ret_str += '<div class="reply-header link">/{}/ - {}</div>' \
                       '<div class="reply-break"></div>'.format(
                message.thread.chan.label,
                message.thread.chan.description)

        ret_str += '<div class="reply-header themed">{}</div>' \
                   '<div class="reply-break"></div>'.format(
                    generate_popup_post_header(message, external_thread=external_thread))

        ret_str += generate_popup_post_body_file_info(message)

        if message.popup_html and not message.regenerate_popup_html:
            ret_str += message.popup_html
        else:
            with session_scope(config.DB_PATH) as new_session:
                message_edit = new_session.query(Messages).filter(
                    Messages.message_id == message.message_id).first()
                message_edit.popup_html = generate_popup_post_html(message)
                if message.regenerate_popup_html:
                    message_edit.regenerate_popup_html = False
                new_session.commit()
                ret_str += message_edit.popup_html

        ret_str += '</div></a>'
    except:
        logger.exception("Could not generate popup html")
        ret_str = card_text

    return ret_str
