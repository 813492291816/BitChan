import html
import logging
import os
import re
import tempfile

import gnupg

from config import DB_PATH
from config import GPG_DIR
from database.models import PGP
from database.utils import session_scope
from utils.files import delete_file
from utils.general import get_random_alphanumeric_string

logger = logging.getLogger("bitchan.gpg")


def find_gpg(text):
    """Find GPG strings"""
    replacements = {
        "pgp_messages": {},
        "pgp_signed_messages": {},
        "pgp_signatures": {},
        "pgp_public_keys": {}
    }

    for each_find in re.findall(r"""(?s)-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----.*?""", text):
        rand_id = f"PGP-{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}"
        text = text.replace(each_find, rand_id, 1)

        replacements["pgp_messages"][rand_id] = {
            "raw_string": html.unescape(each_find.replace("<br/>", "\n")),
            "decrypted": False,
            "decrypted_text": None,
            "signature": None
        }

    for each_find in re.findall(r"""(?s)-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----.*?""", text):
        rand_id = f"PGP-{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}"
        fingerprint = None
        key_info = get_key_info(each_find)
        text = text.replace(each_find, rand_id, 1)
        if key_info:
            fingerprint = key_info["fingerprint"]

        replacements["pgp_public_keys"][rand_id] = {
            "raw_string": html.unescape(each_find.replace("<br/>", "\n")),
            "fingerprint": fingerprint,
            "key_info": key_info
        }

    for each_find in re.findall(r"""(?s)-----BEGIN PGP SIGNED MESSAGE-----.*?-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----.*?""", text):
        rand_id = f"PGP-{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}"
        text = text.replace(each_find, rand_id, 1)

        replacements["pgp_signed_messages"][rand_id] = {
            "raw_string": html.unescape(each_find.replace("<br/>", "\n")),
            "verified": False,
            "verification_info": None,
            "recipients_fingerprints": None
        }

    for each_find in re.findall(r"""(?s)-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----.*?""", text):
        rand_id = f"PGP-{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}"
        text = text.replace(each_find, rand_id, 1)

        replacements["pgp_signatures"][rand_id] = {
            "raw_string": html.unescape(each_find.replace("<br/>", "\n")),
        }

    return text, replacements


def gpg_decrypt(gpg_texts):
    """Decrypt PGP texts"""
    gpg = gnupg.GPG(gnupghome=GPG_DIR)

    if not gpg_texts:
        return gpg_texts

    gpg_tests_iter = gpg_texts

    if "pgp_messages" in gpg_tests_iter:
        for each_id, pgp_msg_info in gpg_tests_iter["pgp_messages"].items():
            if not gpg_texts["pgp_messages"][each_id]["decrypted"]:
                decrypted_msg = None
                decrypt_pgp_id = None
                recipients = gpg.get_recipients(pgp_msg_info["raw_string"])

                with session_scope(DB_PATH) as new_session:
                    # Find recipients and first key that can decrypt the message
                    for each_pgp in new_session.query(PGP).all():
                        try:
                            gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=each_pgp.keyring_name)
                            decrypted_msg_test = gpg.decrypt(
                                pgp_msg_info["raw_string"], passphrase=each_pgp.passphrase)
                            if decrypted_msg_test.ok:
                                if not decrypt_pgp_id:  # Save the first that can decrypt
                                    decrypt_pgp_id = each_pgp.id
                                if each_pgp.key_id not in recipients:
                                    recipients.append(each_pgp.key_id)
                        except:
                            logger.exception("decrypting PGP")

                    if decrypt_pgp_id:
                        pgp_entry = new_session.query(PGP).filter(PGP.id == decrypt_pgp_id).first()
                        if pgp_entry:
                            # Use all keyrings so if the message is signed, the proper public key will be found
                            gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=get_all_keyrings())
                            decrypted_msg = gpg.decrypt(
                                pgp_msg_info["raw_string"], passphrase=pgp_entry.passphrase)

                if decrypted_msg is not None and decrypted_msg.ok:
                    gpg_texts["pgp_messages"][each_id]["decrypted"] = True
                    gpg_texts["pgp_messages"][each_id]["decrypted_text"] = str(decrypted_msg)

                    if decrypted_msg.signature_id:
                        gpg_texts["pgp_messages"][each_id]["signature"] = f"<br/>" \
                          f"Username: {decrypted_msg.username}" \
                          f"<br/>Key ID: {decrypted_msg.key_id}" \
                          f"<br/>Signature ID: {decrypted_msg.signature_id}" \
                          f"<br/>Fingerprint: {decrypted_msg.fingerprint}" \
                          f"<br/>Trust Level: {decrypted_msg.trust_level}" \
                          f"<br/>Trust Text: {decrypted_msg.trust_text}"

                gpg_texts["pgp_messages"][each_id]["recipients_fingerprints"] = recipients


    if "pgp_public_keys" in gpg_tests_iter:
        pass

    if "pgp_signed_messages" in gpg_tests_iter:
        gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=get_all_keyrings())
        for each_id, pgp_msg_info in gpg_tests_iter["pgp_signed_messages"].items():
            if not gpg_texts["pgp_signed_messages"][each_id]["verified"]:
                verified_sig_msg = gpg.verify(gpg_texts["pgp_signed_messages"][each_id]["raw_string"])
                if verified_sig_msg:
                    gpg_texts["pgp_signed_messages"][each_id]["verified"] = True
                    gpg_texts["pgp_signed_messages"][each_id]["verification_info"] = str(verified_sig_msg.sig_info)
                else:
                    gpg_texts["pgp_signed_messages"][each_id]["verified"] = False
                    gpg_texts["pgp_signed_messages"][each_id]["verification_info"] = f"<br/>" \
                        f"Valid: {verified_sig_msg.valid}" \
                        f"<br/>Fingerprint: {verified_sig_msg.fingerprint}" \
                        f"<br/>Creation date: {verified_sig_msg.creation_date}" \
                        f"<br/>Time stamp: {verified_sig_msg.timestamp}" \
                        f"<br/>Signature id: {verified_sig_msg.signature_id}" \
                        f"<br/>Key id: {verified_sig_msg.key_id}" \
                        f"<br/>Status: {verified_sig_msg.status}" \
                        f"<br/>Public key fingerprint: {verified_sig_msg.pubkey_fingerprint}" \
                        f"<br/>Signature timestamp: {verified_sig_msg.sig_timestamp}" \
                        f"<br/>Trust text: {verified_sig_msg.trust_text}" \
                        f"<br/>Trust level: {verified_sig_msg.trust_level}"

    if "pgp_signatures" in gpg_tests_iter:
        pass

    return gpg_texts


def gpg_process_texts(body, gpg_texts):
    if not gpg_texts:
        return body

    if "pgp_messages" in gpg_texts:
        texts = gpg_texts["pgp_messages"]
        for each_id in texts:
            if "decrypted" not in texts[each_id] or "raw_string" not in texts[each_id]:
                continue

            if "recipients_fingerprints" in texts[each_id]:
                # Generate recipient list with detailed info
                list_recipients = []
                for i, fingerprint in enumerate(texts[each_id]["recipients_fingerprints"], start=1):
                    key = get_key_from_fingerprint(fingerprint)
                    if key:
                        list_recipients.append(f"{i}. {key['uids'][0]} ({fingerprint})")
                    else:
                        list_recipients.append(f"{i}. {fingerprint} (key not in keyring)")
                recipients = "<br/>".join(list_recipients)
            else:
                recipients = "None Found"

            raw_string_html = html.escape(texts[each_id]["raw_string"]).replace("\n", "<br/>")

            signature = ""
            sign_text = ""
            if "signature" in texts[each_id] and texts[each_id]["signature"]:
                signature = f'<br/><br/>Signature:{texts[each_id]["signature"]}'
                sign_text = " (Signed)"

            if texts[each_id]["decrypted"]:
                decrypted_text = texts[each_id]["decrypted_text"].replace("\n", "<br/>")

                gen_str = f'<div class="gpg-outer">{decrypted_text}<details class="gpg-detail"><summary>GPG Message{sign_text}</summary>' \
                          f'<div class="gpg-inner">Recipients:<br/>{recipients}' \
                          f'{signature}' \
                          f'<br/><br/>{raw_string_html}' \
                          f'</div></details></div>'
            else:
                gen_str = f'<div class="gpg-outer"><details class="gpg-detail"><summary>GPG Message (could not decrypt)</summary>' \
                          f'<div class="gpg-inner">Recipients:<br/>{recipients}' \
                          f'{signature}' \
                          f'<br/><br/>{raw_string_html}' \
                          f'</div></details></div>'

            body = body.replace(each_id, gen_str)

    if "pgp_signed_messages" in gpg_texts:
        texts = gpg_texts["pgp_signed_messages"]
        for each_id in texts:
            if "verified" not in texts[each_id] or "verification_info" not in texts[each_id] or "raw_string" not in texts[each_id]:
                continue
            raw_string_html = html.escape(texts[each_id]["raw_string"]).replace("\n", "<br/>")
            sig_msg_body = signed_message_get_msg(texts[each_id]["raw_string"])
            if texts[each_id]["verified"]:
                gen_str = f'<div class="gpg-outer">{sig_msg_body}<details class="gpg-detail"><summary>GPG Signed Message (verified)</summary>' \
                          f'<div class="gpg-inner">{raw_string_html}<br/><br/>{texts[each_id]["verification_info"]}</div></details></div>'
            else:
                gen_str = f'<div class="gpg-outer">{sig_msg_body}<details class="gpg-detail"><summary>GPG Signed Message (unverified)</summary>' \
                          f'<div class="gpg-inner">{raw_string_html}<br/>{texts[each_id]["verification_info"]}</div></details></div>'
            body = body.replace(each_id, gen_str)

    if "pgp_signatures" in gpg_texts:
        texts = gpg_texts["pgp_signatures"]
        for each_id in texts:
            raw_string_html = html.escape(texts[each_id]["raw_string"]).replace("\n", "<br/>")
            gen_str = f'<div class="gpg-outer"><details class="gpg-detail"><summary>GPG Signature</summary>' \
                      f'<div class="gpg-inner">{raw_string_html}</div></details></div>'
            body = body.replace(each_id, gen_str)

    if "pgp_public_keys" in gpg_texts:
        texts = gpg_texts["pgp_public_keys"]
        for each_id in texts:
            raw_string_html = html.escape(texts[each_id]["raw_string"]).replace("\n", "<br/>")
            key_info = get_key_info(texts[each_id]["raw_string"])
            if key_info:
                info = generate_key_strings(key_info)
                if is_fingerprint_in_keyring(key_info["fingerprint"]):
                    gen_str = f'<div class="gpg-outer">PGP Public Key<details class="gpg-detail"><summary>{info["uids"]}GPG Public Key (in keyring)</summary>' \
                              f'<div class="gpg-inner">{info["info"]}<br/>{raw_string_html}</div></details></div>'
                else:
                    gen_str = f'<div class="gpg-outer">PGP Public Key<details class="gpg-detail"><summary>{info["uids"]}GPG Public Key (not in keyring)</summary>' \
                              f'<div class="gpg-inner">{info["info"]}<br/>{raw_string_html}</div></details></div>'
            else:
                gen_str = f'<div class="gpg-outer">PGP Public Key<details class="gpg-detail"><summary>GPG Public Key (malformed)</summary>' \
                          f'<div class="gpg-inner">{raw_string_html}</div></details></div>'
            body = body.replace(each_id, gen_str)

    return body


def signed_message_get_msg(gpg_text):
    line_opener = "-----BEGIN PGP SIGNED MESSAGE-----"
    line_opener_passed = False
    line_hash = "Hash:"
    line_hash_passed = False
    line_closer = "-----BEGIN PGP SIGNATURE-----"
    list_lines = []

    for each_line in gpg_text.split("\n"):
        if not line_opener_passed and line_opener in each_line:
            line_opener_passed = True
            continue
        elif not line_hash_passed and line_hash in each_line:
            line_hash_passed = True
            continue
        elif line_closer in each_line:
            break
        list_lines.append(each_line)

    return '\n'.join(list_lines)


def get_all_keyrings():
    key_rings = []
    for file in os.listdir(GPG_DIR):
        if file.endswith('.kr'):
            key_rings.append(file)
    return key_rings


def get_all_key_information():
    list_public_keys = []
    list_private_keys = []
    private_key_ids = []
    public_key_ids = []
    exported_public_keys = {}

    ensure_gpg_dir_exists()

    key_rings = get_all_keyrings()

    for key_ring in key_rings:
        gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=key_ring)

        if key_ring == 'public.kr':
            public_keys = gpg.list_keys()

            for each_key in public_keys:
                if each_key not in list_public_keys:
                    list_public_keys.append(each_key)
                if each_key["keyid"] not in public_key_ids:
                    public_key_ids.append(each_key["keyid"])

            exported_public_keys = get_exported_public_keys(
                gpg, public_keys, exported_public_keys)

        else:
            public_keys = gpg.list_keys()
            private_keys = gpg.list_keys(secret=True)

            for each_key in private_keys:
                if each_key not in list_private_keys:
                    list_private_keys.append(each_key)
                if each_key["keyid"] not in private_key_ids:
                    private_key_ids.append(each_key["keyid"])

            for each_key in public_keys:
                if each_key not in list_public_keys:
                    list_public_keys.append(each_key)
                if each_key["keyid"] not in public_key_ids:
                    public_key_ids.append(each_key["keyid"])

            exported_public_keys = get_exported_public_keys(
                gpg, public_keys, exported_public_keys)

    return list_public_keys, list_private_keys, private_key_ids, public_key_ids, exported_public_keys


def get_key_from_fingerprint(fingerprint_keyid):
    gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=get_all_keyrings())

    for key in gpg.list_keys() + gpg.list_keys(True):
        if fingerprint_keyid in [key['fingerprint'], key['keyid']]:
            return key


def get_key_info(key_string):
    gpg = gnupg.GPG(gnupghome=GPG_DIR)
    key_string = key_string.replace('<br/>', '\n')

    with tempfile.TemporaryDirectory() as tmpdir:
        path_file = f"{tmpdir}/{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}"

        with open(path_file, 'w', encoding='utf-8') as f:
            f.write(key_string)

        scanned_key = gpg.scan_keys(path_file)
        delete_file(path_file)

        if scanned_key:
            return scanned_key[0]


def generate_key_strings(key_info):
    info_str = ""
    for key, value in key_info.items():
        value_str = f"{value}"
        info_str += f"{key}: {html.escape(value_str)}<br/>"

    uids = ""
    if key_info["uids"]:
        uids = ", ".join(key_info["uids"])
        uids += ": "

    return {"info": info_str, "uids": html.escape(uids)}


def get_keyring_fingerprints():
    pub_keyring_fingerprints = []
    gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=get_all_keyrings())

    for key in gpg.list_keys():
        pub_keyring_fingerprints.append(key['fingerprint'])

    return pub_keyring_fingerprints


def get_keyring_name(fingerprint):
    list_keyrings = []

    if type(fingerprint) == str:
        list_fingerprints = [fingerprint]
    else:
        list_fingerprints = fingerprint

    ensure_gpg_dir_exists()

    key_rings = get_all_keyrings()

    for key_ring in key_rings:
        gpg_public = gnupg.GPG(gnupghome=GPG_DIR, keyring=key_ring)

        for each_key in gpg_public.list_keys() + gpg_public.list_keys(secret=True):
            for each_fingerprint in list_fingerprints:
                if each_key["fingerprint"] == each_fingerprint:
                    list_keyrings.append(key_ring)

    return list_keyrings


def get_key_id(keyring, fingerprint):
    gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=keyring)
    for each_key in gpg.list_keys() + gpg.list_keys(secret=True):
        if fingerprint == each_key["fingerprint"]:
            return each_key["keyid"]


def is_fingerprint_in_keyring(fingerprint):
    if fingerprint in get_keyring_fingerprints():
        return True
    else:
        return False


def import_key(key):
    # Determine whether key is public or private
    if re.findall(r"""(?s)-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----.*?""", key):
        gpg_public = gnupg.GPG(gnupghome=GPG_DIR, keyring='public.kr')
        return 'public.kr', gpg_public.import_keys(key)

    elif re.findall(r"""(?s)-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----.*?""", key):
        keyring_name = f'{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}.kr'
        gpg_private = gnupg.GPG(gnupghome=GPG_DIR, keyring=keyring_name)
        return keyring_name, gpg_private.import_keys(key)

    return None, None


def delete_public_key(fingerprint):
    list_returns = []
    list_keyrings = get_keyring_name(fingerprint) + ['public.kr']
    for each_keyring in list_keyrings:
        gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=each_keyring)
        list_returns.append(str(gpg.delete_keys(fingerprint)))
    return list_returns


def get_exported_public_keys(gpg_, list_pub_keys, list_exports):
    """Return dict of exported public keys"""
    for pub_key in list_pub_keys:
        list_exports[pub_key["keyid"]] = gpg_.export_keys(pub_key["keyid"])
    return list_exports


def ensure_gpg_dir_exists(overwrite_conf=True):
    if not os.path.exists(GPG_DIR):
        os.mkdir(GPG_DIR)

    gnupg.GPG(gnupghome=GPG_DIR)

    if not os.path.exists(f'{GPG_DIR}/gpg.conf') or overwrite_conf:
        # Create gpg.conf and add option to disable trust requirement for encrypting to public keys
        # which don't have a corresponding private key in keyring
        file_object = open(f'{GPG_DIR}/gpg.conf', 'a')
        file_object.write('trust-model always\n')
        file_object.close()

        # Create gpg-agent.conf and add options to allow multiple private keys to be tested on encrypted
        # messages
        file_object = open(f'{GPG_DIR}/gpg-agent.conf', 'a')
        file_object.write('default-cache-ttl 0\n')
        file_object.write('max-cache-ttl 0\n')
        file_object.close()
