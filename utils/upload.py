import json
import logging
import subprocess
import time
from io import BytesIO

import certifi
import pycurl

import config
from config import DATABASE_BITCHAN
from database.models import UploadProgress
from database.utils import session_scope

DB_PATH = 'sqlite:///' + DATABASE_BITCHAN

logger = logging.getLogger("bitchan.upload")


class UploadCurl:
    def __init__(self, upload_id):
        self.update_timestamp = time.time()
        self.upload_id = upload_id

    def progress(self, download_t, download_d, upload_t, upload_d):
        now = time.time()
        if self.update_timestamp < now:
            while self.update_timestamp < now:
                self.update_timestamp += 5
            with session_scope(DB_PATH) as new_session:
                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == self.upload_id).first()
                if upl and upload_d > upl.progress_size_bytes:
                    upl.progress_size_bytes = upload_d
                    upl.progress_percent = upload_d / upload_t * 100
                    new_session.commit()
                    logger.info("Upload {}: {}/{} ({:.1f} %) uploaded".format(
                        upl.upload_id,
                        upl.progress_size_bytes,
                        upl.total_size_bytes,
                        upl.progress_percent))

    def upload_curl(self,
            post_id, domain, uri, file_path,
            download_prefix=None,
            upload_word="files[]",
            response=None):
        upload_url = None
        buffer = BytesIO()

        c = pycurl.Curl()
        c.setopt(c.NOPROGRESS, False)
        c.setopt(c.XFERINFOFUNCTION, self.progress)
        c.setopt(c.URL, uri)
        c.setopt(c.HTTPPOST, [(upload_word, (c.FORM_FILE, file_path))])
        c.setopt(c.CAINFO, certifi.where())
        c.setopt(c.WRITEDATA, buffer)

        c.setopt(pycurl.PROXY, '172.28.1.2')
        c.setopt(pycurl.PROXYPORT, 9060)
        c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)

        c.perform()
        c.close()

        body = buffer.getvalue()
        logger.info("pycurl returned: {}".format(body.decode("UTF-8")))

        if response == "JSON":
            try:
                response_json = json.loads(body)
            except:
                logger.error("{}: Could not parse JSON".format(post_id))
                response_json = None

            if response_json:
                # v2.femto.pw
                if "data" in response_json and "short" in response_json["data"]:
                    upload_url = "{}/{}".format(
                        download_prefix, response_json["data"]["short"])

                # pomf/uguu
                if "success" in response_json and response_json["success"]:
                    try:
                        if download_prefix:
                            upload_url = "{}/{}".format(
                                download_prefix, response_json["files"][0]["url"])
                        elif response_json["files"][0]["url"].startswith("http"):
                            upload_url = response_json["files"][0]["url"]
                    except:
                        pass
        elif response == "str_url":
            if domain in body.decode():
                upload_url = body.decode()

        if upload_url:
            return True, upload_url
        return False, None


def upload_curl_deprecated(
        post_id, domain, uri, file_path,
        download_prefix=None,
        extra_curl_options=None,
        upload_word="files[]",
        response=None):
    upload_url = None

    curl_list = [
        "curl",
        "-k",
        "--socks5-hostname",
        "{host}:{port}".format(host=config.TOR_HOST, port=config.TOR_SOCKS_PORT)
    ]
    if extra_curl_options:
        curl_list = curl_list + extra_curl_options.split(" ")
    curl_list.append("-F")
    curl_list.append("{}=@{}".format(upload_word, file_path))
    curl_list.append(uri)

    logger.info("{}: curl command: {}".format(post_id, " ".join(curl_list)))

    p = subprocess.Popen(curl_list, stdout=subprocess.PIPE)
    out, err = p.communicate()

    logger.error("{}: curl response: {}".format(post_id, out))

    if response == "JSON":
        try:
            response_json = json.loads(out)
        except:
            logger.error("{}: Could not parse JSON".format(post_id))
            response_json = None

        if response_json:
            # v2.femto.pw
            if "data" in response_json and "short" in response_json["data"]:
                upload_url = "{}/{}".format(
                    download_prefix, response_json["data"]["short"])

            # pomf/uguu
            if "success" in response_json and response_json["success"]:
                try:
                    if download_prefix:
                        upload_url = "{}/{}".format(
                            download_prefix, response_json["files"][0]["url"])
                    elif response_json["files"][0]["url"].startswith("http"):
                        upload_url = response_json["files"][0]["url"]
                except:
                    pass
    elif response == "str_url":
        if domain in out.decode():
            upload_url = out.decode()

    if upload_url:
        return True, upload_url
    return False, None
