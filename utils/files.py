import base64
import logging
import os
import random
import subprocess
import time
import zipfile
from contextlib import closing
from zipfile import ZipFile

import filelock
from PIL import Image
from PIL import ImageFile

import config
from config import FILE_DIRECTORY

logger = logging.getLogger('bitchan.files')


def extract_zip(message_id, zfile, extract_dir):
    logger.info("{}: Extracting {} to {}".format(message_id[-config.ID_LENGTH:].upper(), zfile, extract_dir))
    with zipfile.ZipFile(zfile, 'r') as zipObj:
        zipObj.extractall(extract_dir)
    logger.info("{}: Finished extracting".format(message_id[-config.ID_LENGTH:].upper()))


def count_files_in_zip(message_id, zip_file):
    with closing(ZipFile(zip_file)) as archive:
        count = len(archive.infolist())
        logger.info("{}: {} files found in zip archive".format(message_id[-config.ID_LENGTH:].upper(), count))
        return count


def data_extract_file(file_source, extract_size, extract_start, chunk=1000):
    logger.info("Extracting {} bytes from file of {} bytes at position {}".format(
        extract_size, os.path.getsize(file_source), extract_start))
    file_size = os.path.getsize(file_source)
    position = 0
    extracted = False
    data_extracted_base64 = None

    with open(file_source, 'rb') as in_file:
        os.unlink(file_source)
        with open(file_source, 'wb') as out_file:
            while position < file_size:
                if position == extract_start:
                    logger.info("At extraction point: extracting {}".format(extract_size))
                    data_extracted_base64 = base64.b64encode(
                        in_file.read(extract_size)).decode()
                    extracted = True
                    position += extract_size
                elif position + chunk > extract_start and not extracted:
                    new_chunk = extract_start - position
                    logger.info("Smaller chunk to meet start: {}".format(new_chunk))
                    out_file.write(in_file.read(new_chunk))
                    position += new_chunk
                else:
                    logger.info("Normal chunk: {}".format(chunk))
                    out_file.write(in_file.read(chunk))
                    position += chunk
    return data_extracted_base64


def data_insert_file(file_source, insert_data, insert_start, chunk=1000):
    logger.info("Inserting {} bytes into file of {} bytes at position {}".format(
        len(insert_data), os.path.getsize(file_source), insert_start))
    total_size = os.path.getsize(file_source) + len(insert_data)
    inserted = False
    position = 0

    with open(file_source, 'rb') as in_file:
        os.unlink(file_source)
        with open(file_source, 'wb') as out_file:
            while position < total_size:
                if position == insert_start:
                    logger.info("At insert point: add {}".format(len(insert_data)))
                    inserted = True
                    out_file.write(insert_data)
                    position += len(insert_data)
                elif position + chunk > insert_start and not inserted:
                    new_chunk = insert_start - position
                    logger.info("Smaller chunk to meet start: {}".format(new_chunk))
                    out_file.write(in_file.read(new_chunk))
                    position += new_chunk
                else:
                    logger.info("Normal chunk: {}".format(chunk))
                    out_file.write(in_file.read(chunk))
                    position += chunk


def data_file_multiple_extract(file_source, extract_starts_sizes, chunk=1000):
    for each_size_start in extract_starts_sizes:
        logger.info("Extracting from file of {} bytes: {} bytes at position {}".format(
            os.path.getsize(file_source), each_size_start["size"], each_size_start["start"]))
    file_size = os.path.getsize(file_source)
    position = 0
    extracted = [False for _ in range(len(extract_starts_sizes))]
    extract_index = 0
    data_extracted_start_base64 = []

    with open(file_source, 'rb') as in_file:
        os.unlink(file_source)
        with open(file_source, 'wb') as out_file:
            while position < file_size:
                if (extract_index < len(extract_starts_sizes) and
                        position == extract_starts_sizes[extract_index]["start"]):
                    logger.info("Pos: {}. At extraction point: extract {} bytes".format(
                        position, extract_starts_sizes[extract_index]["size"]))
                    data_extracted_start_base64.append({
                        "start": extract_starts_sizes[extract_index]["start"],
                        "data": base64.b64encode(
                            in_file.read(extract_starts_sizes[extract_index]["size"])).decode()
                    })
                    extracted[extract_index] = True
                    position += extract_starts_sizes[extract_index]["size"]
                    extract_index += 1
                elif (extract_index < len(extract_starts_sizes) and
                        position + chunk > extract_starts_sizes[extract_index]["start"] and
                        not extracted[extract_index]):
                    new_chunk = extract_starts_sizes[extract_index]["start"] - position
                    logger.info("Pos: {}. Smaller chunk to meet start: {}".format(position, new_chunk))
                    out_file.write(in_file.read(new_chunk))
                    position += new_chunk
                else:
                    logger.info("Pos: {}. Normal chunk: {}".format(position, chunk))
                    out_file.write(in_file.read(chunk))
                    position += chunk
    return data_extracted_start_base64


def data_file_multiple_insert(file_source, insert_starts_data, chunk=1000):
    total_size = os.path.getsize(file_source)
    for each_start_data in insert_starts_data:
        logger.info("Inserting into file of {} bytes: {} bytes at position {}".format(
            os.path.getsize(file_source),
            len(base64.b64decode(each_start_data["data"])),
            each_start_data["start"]))
        total_size += len(each_start_data["data"])
    inserted = [False for _ in range(len(insert_starts_data))]
    insert_index = 0
    position = 0

    with open(file_source, 'rb') as in_file:
        os.unlink(file_source)
        with open(file_source, 'wb') as out_file:
            while position < total_size:
                if (insert_index < len(insert_starts_data) and
                        position == insert_starts_data[insert_index]["start"]):
                    logger.info("Pos: {}. At insertion point: {} bytes".format(
                        position, len(base64.b64decode(insert_starts_data[insert_index]["data"]))))
                    out_file.write(base64.b64decode(insert_starts_data[insert_index]["data"]))
                    inserted[insert_index] = True
                    position += len(base64.b64decode(insert_starts_data[insert_index]["data"]))
                    insert_index += 1
                elif (insert_index < len(insert_starts_data) and
                        position + chunk > insert_starts_data[insert_index]["start"] and
                        not inserted[insert_index]):
                    new_chunk = insert_starts_data[insert_index]["start"] - position
                    logger.info("Pos: {}. Smaller chunk to meet start: {}".format(position, new_chunk))
                    out_file.write(in_file.read(new_chunk))
                    position += new_chunk
                else:
                    logger.info("Pos: {}. Normal chunk: {}".format(position, chunk))
                    out_file.write(in_file.read(chunk))
                    position += chunk


def return_non_overlapping_sequences(
        number_sequences,
        sequence_start,
        sequence_end,
        size_start,
        size_end):
    res = []
    for _ in range(number_sequences):
        while True:
            pos = random.randint(sequence_start, sequence_end)
            size = random.randint(size_start, size_end)
            reject = False
            if pos + size > sequence_end:
                reject = True
            for x_pos, x_size in res:
                if (pos + size > sequence_end or
                        x_pos <= pos <= x_pos + x_size or
                        x_pos <= pos + size <= x_pos + x_size or
                        pos <= x_pos <= pos + size):
                    reject = True
            if not reject:
                break
        res.append((pos, size))

    res.sort(key=lambda x: x[0])
    return res


def delete_file(file_path):
    if os.path.exists(file_path):
        try:
            subprocess.check_call(["srm", "-l", file_path])
        except:
            try:
                os.remove(file_path)
            except:
                logger.error("Could not delete file")


def delete_files_recursive(del_path):
    try:
        subprocess.check_call(["srm", "-rl", del_path])
    except:
        logger.error("Could not delete files recursively")


def delete_message_files(message_id):
    files_path = "{}/{}".format(FILE_DIRECTORY, message_id)
    thumb_path = "{}/{}_thumb".format(FILE_DIRECTORY, message_id)
    delete_files_recursive(files_path)
    delete_files_recursive(thumb_path)


def human_readable_size(size, decimal_places=1):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PiB':
            break
        size /= 1024.0
    if unit in ["B"]:
        decimal_places = 0
    return f"{size:.{decimal_places}f} {unit}"


def generate_thumbnail(message_id, image, thumb, extension):
    try:
        if not os.path.exists(thumb):
            if os.path.getsize(image) < 400000:
                os.symlink(image, thumb)
            else:
                logger.info("{}: Generating thumbnail: {}".format(message_id[-config.ID_LENGTH:].upper(), thumb))
                ImageFile.LOAD_TRUNCATED_IMAGES = True
                if extension in ["jpg", "jpeg"]:
                    image = Image.open(image).convert('RGB')
                else:
                    image = Image.open(image)
                max_size = (250, 250)
                image.thumbnail(max_size)
                image.save(thumb)
        else:
            logger.info("{}: Thumbnail already exists: {}".format(message_id[-config.ID_LENGTH:].upper(), thumb))
    except:
        logger.exception("{}: Generating thumbnail".format(message_id[-config.ID_LENGTH:].upper()))


class LF:
    def __init__(self):
        self.is_lock = {}
        self.fl = {}

    def lock_acquire(self, lf, to):
        logging.getLogger("filelock").setLevel(logging.WARNING)
        self.fl[lf] = filelock.FileLock(lf, timeout=1)
        self.is_lock[lf] = False
        timer = time.time() + to
        logger.debug("lock {} acquiring (try {} sec)".format(lf, to))
        while time.time() < timer:
            try:
                self.fl[lf].acquire()
                sec = time.time() - (timer - to)
                logger.debug("lock {} acquired in {:.4f} sec".format(lf, sec))
                self.is_lock[lf] = True
                break
            except:
                pass
            time.sleep(0.1)

        if not self.is_lock[lf]:
            logger.debug("no lock in {:.1f} sec. breaking.".format(to))
            self.lock_release(lf)
        else:
            return True

    def lock_locked(self, lf):
        if lf not in self.is_lock:
            logger.error("error lf unknown {}".format(lf))
            return False
        return self.is_lock[lf]

    def lock_release(self, lf):
        try:
            time.sleep(0.1)
            logger.debug("releasing {}".format(lf))
            self.fl[lf].release(force=True)
            os.remove(lf)
        except Exception:
            pass
        finally:
            self.is_lock[lf] = False
