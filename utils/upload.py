import subprocess
import json
import logging

logger = logging.getLogger("bitchan.upload")


def upload_curl(
        post_id, domain, uri, file_path,
        download_prefix=None,
        extra_curl_options=None,
        upload_word="files[]",
        response=None):
    upload_url = None

    curl_list = ["curl", "-k", "--socks5-hostname", "172.28.1.2:9060"]
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
