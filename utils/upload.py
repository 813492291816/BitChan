import json
import logging
import os
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
    proxy_types = {
        "tor": {
            "host": config.TOR_HOST,
            "port": config.TOR_SOCKS_PORT,
            "type": pycurl.PROXYTYPE_SOCKS5_HOSTNAME
        },
        "i2p": {
            "host": config.I2P_HOST,
            "port": config.I2P_SOCKS_PORT,
            "type": pycurl.PROXYTYPE_HTTP
        }
    }

    def __init__(self, upload_id):
        self.update_timestamp = time.time()
        self.upload_id = upload_id
        self.file_size = None

    def progress(self, download_t, download_d, upload_t, upload_d):
        now = time.time()
        if self.update_timestamp < now:
            while self.update_timestamp < now:
                self.update_timestamp += 5
            with session_scope(DB_PATH) as new_session:
                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == self.upload_id).first()
                if not upl:
                    logger.error("No upload progress table entry: Cancelling upload")
                    return -1

                if upload_d > upl.progress_size_bytes:
                    try:
                        if not upload_t:
                            if upl.total_size_bytes:
                                upload_t = upl.total_size_bytes
                            elif self.file_size:
                                upload_t = self.file_size
                        upl.progress_size_bytes = upload_d
                        upl.progress_percent = upload_d / upload_t * 100
                        upl.progress_ts = int(time.time())
                        new_session.commit()
                        logger.info("Upload {}: {}/{} ({:.1f} %) uploaded".format(
                            upl.upload_id,
                            upl.progress_size_bytes,
                            upload_t,
                            upl.progress_percent))
                    except Exception as err:
                        logger.error("Exception monitoring upload progress: {}/{} uploaded, {}".format(
                            upload_d, upload_t, err))
                elif upl.progress_ts and time.time() - upl.progress_ts > 60:  # If no upload progress in 60 seconds, end upload
                    logger.error("Upload progress timeout: Cancelling upload")
                    return -1

    def upload_curl(self, post_id, file_path, options):
        download_url = None
        self.file_size = os.path.getsize(file_path)
        buffer = BytesIO()

        c = pycurl.Curl()
        c.setopt(c.URL, options["uri"])
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.NOPROGRESS, False)
        c.setopt(c.XFERINFOFUNCTION, self.progress)

        if options["http_headers"]:
            c.setopt(pycurl.HTTPHEADER, json.loads(options["http_headers"]))

        if options["subtype"] == "simple_upload":
            c.setopt(c.UPLOAD, 1)
            c.setopt(pycurl.READFUNCTION, open(file_path, 'rb').read)
        else:
            c.setopt(c.HTTPPOST, [(options["upload_word"], (c.FORM_FILE, file_path))])
            c.setopt(c.CAINFO, certifi.where())

        proxy_type = options["proxy_type"]
        if not proxy_type or proxy_type not in self.proxy_types:
            proxy_type = "tor"

        c.setopt(pycurl.PROXY, self.proxy_types[proxy_type]["host"])
        c.setopt(pycurl.PROXYPORT, self.proxy_types[proxy_type]["port"])
        c.setopt(pycurl.PROXYTYPE, self.proxy_types[proxy_type]["type"])

        c.perform()
        c.close()

        body = buffer.getvalue()
        logger.info("pycurl returned: {}".format(body.decode("UTF-8").strip()))

        if options["response"] == "JSON":
            try:
                response_json = json.loads(body)
            except:
                logger.error("{}: Could not parse JSON".format(post_id))
                response_json = None

            if response_json:
                if options["json_key"] and options["json_key"] in response_json:
                    download_url = response_json[options["json_key"]]

                # v2.femto.pw
                elif "data" in response_json and "short" in response_json["data"]:
                    download_url = "{}/{}".format(
                        options["download_prefix"], response_json["data"]["short"])

                # pomf/uguu
                elif "success" in response_json and response_json["success"]:
                    try:
                        if options["download_prefix"]:
                            download_url = "{}/{}".format(
                                options["download_prefix"], response_json["files"][0]["url"])
                        elif response_json["files"][0]["url"].startswith("http"):
                            download_url = response_json["files"][0]["url"]
                    except:
                        pass
        elif options["response"] == "str_url":
            if body.decode().startswith("http"):
                download_url = body.decode()

        if download_url:
            if options["replace_download_domain"]:  # For download URLs that need the domain replaced
                dom_replace = json.loads(options["replace_download_domain"])
                download_url = download_url.replace(dom_replace[0], dom_replace[1])
                logger.info("Domain replaced: {}".format(download_url.strip()))
            return True, download_url
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
