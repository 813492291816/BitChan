import logging

import config
from bitchan_client import DaemonCom

logger = logging.getLogger('bitchan.message_check')
daemon_com = DaemonCom()


def check_msg_dict_post(errors, dict_msg):
    post_dict_keys = [
        "version",
        "message_type",
        "is_op",
        "op_sha256_hash",
        "timestamp_utc",
        "file_size",
        "file_amount",
        "file_url_type",
        "file_url",
        "file_upload_settings",
        "file_extracts_start_base64",
        "file_base64",
        "file_sha256_hash",
        "file_enc_cipher",
        "file_enc_key_bytes",
        "file_enc_password",
        "file_order",
        "image1_spoiler",
        "image2_spoiler",
        "image3_spoiler",
        "image4_spoiler",
        "delete_password_hash",
        "upload_filename",
        "sage",
        "game",
        "game_over",
        "game_hash",
        "game_password_a",
        "game_password_b_hash",
        "game_player_move",
        "game_termination_password",
        "game_termination_pw_hash",
        "subject",
        "message",
        "nation",
        "nation_base64",
        "nation_name",
        "thread_hash",
    ]

    for key in post_dict_keys:
        if key not in dict_msg:
            errors.append("Key {} not found in message dict".format(key))

    if dict_msg["version"] < config.VERSION_MIN_MSG:
        errors.append("Message version too old ({} < {})".format(
            dict_msg["version"], config.VERSION_MIN_MSG))

    if dict_msg["version"] > config.VERSION_BITCHAN:
        errors.append("Message version too new ({} > {})".format(
            dict_msg["version"], config.VERSION_BITCHAN))

    if dict_msg["message_type"] != "post":
        errors.append("Unknown message_type: {}".format(dict_msg["message_type"]))

    if not dict_msg["subject"]:
        errors.append("subject missing from message_dict")

    if dict_msg["is_op"]:
        if not dict_msg["message"] and not dict_msg["file_amount"]:
            errors.append("A comment or file attachment is required to post")
    else:
        if ((not dict_msg["message"] and not dict_msg["file_amount"]) and
                not (dict_msg["game"] or dict_msg["game_player_move"])):
            errors.append("A comment or file attachment is required to post")

    return errors
