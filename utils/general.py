import hashlib
import html
import json
import logging
import random
import string
import time

from config import DICT_PERMISSIONS
from config import LABEL_LENGTH
from config import DESCRIPTION_LENGTH

logger = logging.getLogger('bitchan.utils.general')


def version_checker(version_1: str, version_2: str):
    """
    Compares two versions and returns if version_1 is
    greater, less, or equal to version 2
    """
    try:
        version_1 = version_1.split(".", 2)
        for i, each_number in enumerate(version_1):
            version_1[i] = int(each_number)
    except:
        return "Error", "Malformed version 1"

    try:
        version_2 = version_2.split(".", 2)
        for i, each_number in enumerate(version_2):
            version_2[i] = int(each_number)
    except:
        return "Error", "Malformed version 2"

    if version_1[0] > version_2[0]:
        return "Success", "greater"
    elif version_1[0] < version_2[0]:
        return "Success", "less"

    elif version_1[1] > version_2[1]:
        return "Success", "greater"
    elif version_1[1] < version_2[1]:
        return "Success", "less"

    elif version_1[2] > version_2[2]:
        return "Success", "greater"
    elif version_1[2] < version_2[2]:
        return "Success", "less"

    return "Success", "equal"


def get_thread_id(text_str):
    sha256 = hashlib.sha256()
    sha256.update(text_str.encode())
    thread_id = sha256.hexdigest()
    return thread_id


def get_random_alphanumeric_string(length, with_punctuation=True, with_digits=True, with_spaces=True,):
    letters_and_digits = string.ascii_letters
    if with_punctuation:
        letters_and_digits += string.punctuation
    if with_digits:
        letters_and_digits += string.digits
    if with_spaces:
        letters_and_digits += " "
    return ''.join((random.choice(letters_and_digits) for i in range(length)))


def generate_passphrase(
        access: str,
        chan_type: str,
        label: str,
        description: str,
        restrict_access: list,
        primary_access: list,
        secondary_access: list,
        tertiary_access: list,
        rules: dict,
        extra_string: str):
    return json.dumps([
        access,
        chan_type,
        label,
        description,
        restrict_access,
        primary_access,
        secondary_access,
        tertiary_access,
        rules,
        extra_string
    ])


def process_passphrase(passphrase):
    errors = []
    rules_dict = {}

    if not passphrase:
        errors.append("Passphrase cannot be empty")
        return errors, {}

    try:
        list_passphrase = json.loads(passphrase)
    except Exception as err:
        errors.append("Passphrase does not represent a JSON string: {}".format(err))
        return errors, {}

    try:
        if len(list_passphrase) < 7:
            errors.append("Not enough items in passphrase")
            return errors, {}

        if not isinstance(list_passphrase[0], str):
            errors.append("Access is not string: {}".format(type(list_passphrase[0])))

        if not isinstance(list_passphrase[1], str):
            errors.append("Chan type is not string: {}".format(type(list_passphrase[1])))
        elif "{}_{}".format(list_passphrase[0], list_passphrase[1]) not in [
                "public_board",
                "private_board",
                "public_list",
                "private_list"]:
            errors.append("Unknown access/chan types: {}/{}".format(
                list_passphrase[0], list_passphrase[1]))

        if not isinstance(list_passphrase[2], str):
            errors.append("Label is not string: {}".format(type(list_passphrase[2])))
        elif not list_passphrase[2]:
            errors.append("Label cannot be left blank")
        elif len(list_passphrase[2]) > LABEL_LENGTH:
            errors.append("Label is too long ({}), must be {} or less characters.".format(
                len(list_passphrase[2]), LABEL_LENGTH))

        if not isinstance(list_passphrase[3], str):
            errors.append("Description is not string: {}".format(type(list_passphrase[3])))
        elif len(list_passphrase[3]) > DESCRIPTION_LENGTH:
            errors.append("Description is too long ({}), must be {} or less characters.".format(
                len(list_passphrase[3]), DESCRIPTION_LENGTH))

        if not isinstance(list_passphrase[4], list):
            errors.append("Restrict addresses not a list: {}".format(type(list_passphrase[4])))
        elif not isinstance(list_passphrase[5], list):
            errors.append("Primary addresses not a list: {}".format(type(list_passphrase[5])))
        elif not isinstance(list_passphrase[6], list):
            errors.append("Secondary addresses not a list: {}".format(type(list_passphrase[6])))
        elif not isinstance(list_passphrase[7], list):
            errors.append("Tertiary addresses not a list: {}".format(type(list_passphrase[7])))
        elif not isinstance(list_passphrase[8], dict):
            errors.append("Permissions not a dict: {}".format(type(list_passphrase[8])))
        elif not isinstance(list_passphrase[9], str):
            errors.append("Extra String not a str: {}".format(type(list_passphrase[9])))
        else:
            if (list_passphrase[1] in ["private_board", "private_list"] and
                    not list_passphrase[5] and
                    not list_passphrase[6] and
                    not list_passphrase[7]):
                errors.append("Private boards and lists need at least one primary or secondary or tertiary address")
            for each_list_addresses in [list_passphrase[4], list_passphrase[5], list_passphrase[6], list_passphrase[7]]:
                for each_address in each_list_addresses:
                    if not isinstance(each_address, str):
                        errors.append("Address not string: {}, '{}'".format(type(each_address), each_address))
                        continue
                    if not each_address.startswith("BM-"):
                        errors.append("Address does not start with 'BM-': {}".format(each_address))
                    if len(each_address) > 38 or len(each_address) < 34:
                        errors.append("Address incorrect length: {}".format(each_address))

            # HTML escape rules dict keys and values
            for each_key, each_value in list_passphrase[8].items():
                if each_key not in DICT_PERMISSIONS:
                    errors.append("Unknown rule: {}".format(each_key))
                    continue
                else:
                    key = html.escape(each_key)

                # Sanity-check require_identity_to_post
                if (each_key == "require_identity_to_post" and
                        not isinstance(each_value, bool)):
                    errors.append("require_identity_to_post not boolean")
                    continue
                else:
                    value = each_value

                # Sanity-check automatic_wipe
                if each_key == "automatic_wipe":
                    if not isinstance(each_value, dict):
                        errors.append("automatic_wipe not dict")
                        continue
                    elif "wipe_epoch" not in each_value:
                        errors.append("wipe_epoch not in automatic_wipe")
                        continue
                    elif "interval_seconds" not in each_value:
                        errors.append("interval_seconds not in automatic_wipe")
                        continue
                    elif not isinstance(each_value["wipe_epoch"], int):
                        errors.append("wipe_epoch not integer")
                        continue
                    elif not isinstance(each_value["interval_seconds"], int):
                        errors.append("interval_seconds not integer")
                        continue
                    else:
                        value = each_value

                try:
                    rules_dict[key] = value
                except Exception as err:
                    errors.append("Error escaping key or value ('{}': '{}'): {}".format(
                        each_key, each_value, err))
                    continue

    except Exception as err:
        errors.append("Exception: {}".format(err))

    if not errors:
        return [], {
            "access": html.escape(list_passphrase[0]),
            "type": html.escape(list_passphrase[1]),
            "label": html.escape(list_passphrase[2]),
            "description": html.escape(list_passphrase[3]),
            "restricted_addresses": [html.escape(x) for x in list_passphrase[4]],
            "primary_addresses": [html.escape(x) for x in list_passphrase[5]],
            "secondary_addresses": [html.escape(x) for x in list_passphrase[6]],
            "tertiary_addresses": [html.escape(x) for x in list_passphrase[7]],
            "rules": rules_dict,
            "extra_string": html.escape(list_passphrase[9])
        }

    for each_error in errors:
        logger.error(each_error)
    return errors, {}


def set_clear_time_to_future(rules):
    """Set auto clear time to the future"""
    try:
        if ("automatic_wipe" in rules and
                rules["automatic_wipe"]["wipe_epoch"] < time.time()):
            while rules["automatic_wipe"]["wipe_epoch"] < time.time():
                rules["automatic_wipe"]["wipe_epoch"] += \
                    rules["automatic_wipe"]["interval_seconds"]
    finally:
        return rules


def pairs(matches):
    """Grabs pairs of formatting chars for body processing"""
    iters = [iter(matches)] * 2
    return zip(*iters)


def is_int(test_var, _range=None):
    try:
        _ = int(test_var)
    except ValueError:
        return False
    except TypeError:
        return False
    return True


def is_bitmessage_address(address):
    try:
        if (address and
                isinstance(address, str) and
                address.startswith("BM-") and
                34 < len(address) < 38):
            return True
    except:
        return


def check_bm_address_csv_to_list(status_msg, str_addresses):
    try:
        str_addresses = str_addresses.strip()

        list_ = [x.replace(" ", "") for x in str_addresses.split(",")]
        if list_ == [""]:
            list_ = []

        # Check BM address formatting
        for each_address in list_:
            if not is_bitmessage_address(each_address):
                status_msg['status_message'].append(
                    "Invalid address: {}".format(each_address))

        return status_msg, list_
    except Exception as err:
        status_msg['status_message'].append(
            "Malformed address list. Must be in CSV format: {}".format(err))
        return status_msg, None
