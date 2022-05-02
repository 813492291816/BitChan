import hashlib
import html
import json
import logging
import random
import string
import time
import datetime
import config

logger = logging.getLogger('bitchan.general')


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


def get_random_alphanumeric_string(length, with_punctuation=True, with_digits=True, with_spaces=True):
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

        if len(list_passphrase) > 10:
            errors.append("Too many items in passphrase")
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
        elif len(list_passphrase[2]) > config.LABEL_LENGTH:
            errors.append("Label is too long ({}), max is {}.".format(
                len(list_passphrase[2]), config.LABEL_LENGTH))

        if not isinstance(list_passphrase[3], str):
            errors.append("Description is not string: {}".format(type(list_passphrase[3])))
        elif len(list_passphrase[3]) > config.DESCRIPTION_LENGTH:
            errors.append("Description is too long ({}), max is {}.".format(
                len(list_passphrase[3]), config.DESCRIPTION_LENGTH))

        if not isinstance(list_passphrase[4], list):
            errors.append("Restrict addresses not a list: {}".format(type(list_passphrase[4])))
        elif not isinstance(list_passphrase[5], list):
            errors.append("Owner addresses not a list: {}".format(type(list_passphrase[5])))
        elif not isinstance(list_passphrase[6], list):
            errors.append("Admin addresses not a list: {}".format(type(list_passphrase[6])))
        elif not isinstance(list_passphrase[7], list):
            errors.append("User addresses not a list: {}".format(type(list_passphrase[7])))
        elif not isinstance(list_passphrase[8], dict):
            errors.append("Permissions not a dict: {}".format(type(list_passphrase[8])))
        elif not isinstance(list_passphrase[9], str):
            errors.append("Extra String not a str: {}".format(type(list_passphrase[9])))
        else:
            if (list_passphrase[1] in ["private_board", "private_list"] and
                    not list_passphrase[5] and
                    not list_passphrase[6] and
                    not list_passphrase[7]):
                errors.append("Private boards and lists need at least one Owner or Admin or User address")
            for each_list_addresses in [list_passphrase[4], list_passphrase[5], list_passphrase[6], list_passphrase[7]]:
                for each_address in each_list_addresses:
                    if not isinstance(each_address, str):
                        errors.append("Address not string: {}, '{}'".format(type(each_address), each_address))
                        continue
                    if not each_address.startswith("BM-"):
                        errors.append("Address does not start with 'BM-': {}".format(each_address))
                    if len(each_address) > 38 or len(each_address) < 34:
                        errors.append("Address incorrect length: {}".format(each_address))

            # Check addresses length
            if len(",".join(list_passphrase[4])) > config.PASSPHRASE_ADDRESSES_LENGTH:
                errors.append("Restricted Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(list_passphrase[4]))))

            if len(",".join(list_passphrase[5])) > config.PASSPHRASE_ADDRESSES_LENGTH:
                errors.append("Owner Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(list_passphrase[5]))))

            if len(",".join(list_passphrase[6])) > config.PASSPHRASE_ADDRESSES_LENGTH:
                errors.append("Admin Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(list_passphrase[6]))))

            if len(",".join(list_passphrase[7])) > config.PASSPHRASE_ADDRESSES_LENGTH:
                errors.append("User Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(list_passphrase[7]))))

            if len(list_passphrase[9]) > config.PASSPHRASE_EXTRA_STRING_LENGTH:
                errors.append("Extra String is greater than {} characters: {}".format(
                    config.PASSPHRASE_EXTRA_STRING_LENGTH, len(list_passphrase[9])))

            # HTML escape rules dict keys and values
            for each_key, each_value in list_passphrase[8].items():
                if each_key not in config.DICT_PERMISSIONS:
                    errors.append("Unknown Rule: {}".format(each_key))
                    continue
                else:
                    key = html.escape(each_key)

                # Sanity-check require_identity_to_post
                if each_key == "require_identity_to_post":
                    if not isinstance(each_value, bool):
                        errors.append("require_identity_to_post not boolean")
                        continue
                    else:
                        value = each_value

                # Sanity-check allow_list_pgp_metadata
                elif each_key == "allow_list_pgp_metadata":
                    if not isinstance(each_value, bool):
                        errors.append("allow_list_pgp_metadata not boolean")
                        continue
                    else:
                        value = each_value

                # Sanity-check automatic_wipe
                elif each_key == "automatic_wipe":
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
                    elif each_value["wipe_epoch"] > config.WIPE_START_MAX:
                        errors.append("Automatic Wipe Epoch Start Time is greater than year 3020.")
                        continue
                    elif not isinstance(each_value["interval_seconds"], int):
                        errors.append("interval_seconds not integer")
                        continue
                    elif each_value["interval_seconds"] > config.WIPE_INTERVAL_MAX:
                        errors.append("Automatic Wipe Interval is greater than 500 years.")
                        continue
                    else:
                        value = {
                            "wipe_epoch": each_value["wipe_epoch"],
                            "interval_seconds": each_value["interval_seconds"]
                        }
                else:
                    continue

                rules_dict[key] = value

    except Exception as err:
        errors.append("Exception: {}".format(err))

    if not errors:
        return [], {
            "access": html.escape(list_passphrase[0]),
            "type": html.escape(list_passphrase[1]),
            "label": html.escape(list_passphrase[2]),
            "label_unescaped": list_passphrase[2],
            "description": html.escape(list_passphrase[3]),
            "description_unescaped": list_passphrase[3],
            "restricted_addresses": [html.escape(x) for x in list_passphrase[4]],
            "primary_addresses": [html.escape(x) for x in list_passphrase[5]],
            "secondary_addresses": [html.escape(x) for x in list_passphrase[6]],
            "tertiary_addresses": [html.escape(x) for x in list_passphrase[7]],
            "rules": rules_dict,
            "extra_string": html.escape(list_passphrase[9]),
            "extra_string_unescaped": list_passphrase[9]
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


intervals = (
    ('week', 604800),  # 60 * 60 * 24 * 7
    ('day', 86400),    # 60 * 60 * 24
    ('hr', 3600),      # 60 * 60
    ('min', 60),
    ('sec', 1),
)


def display_time(seconds, granularity=2):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip('s')
            result.append("{} {}".format(int(value), name))
    return ', '.join(result[:granularity])


def timestamp_to_date(timestamp):
    return datetime.datetime.fromtimestamp(
        timestamp).strftime('%d %b %Y (%a) %H:%M:%S')
