import logging
import time

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import DeletedMessages
from database.models import ModLog
from database.utils import session_scope
from utils.files import LF
from utils.posts import delete_chan
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.routes import get_logged_in_user_name
from utils.shared import add_mod_log_entry

daemon_com = DaemonCom()

logger = logging.getLogger("bitchan.chan")


def leave_chan(chan_address, clear_mod_log=False):
    logger.info(f"Leaving chan {chan_address}")

    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(
            Chan).filter(Chan.address == chan_address).first()
        admin_cmds = new_session.query(Command).filter(
            Command.chan_address == chan_address).all()

        try:
            response = daemon_com.leave_chan(chan_address)  # Leave chan in Bitmessage
            logger.info(f"Bitmessage response to command to leave chan: {response}")
            if response == "success" or "Specified address is not a chan address" in response:
                # Delete Admin commands
                for each_adm_cmd in admin_cmds:
                    new_session.delete(each_adm_cmd)

                # Delete threads and posts
                for each_thread in chan.threads:
                    for each_message in each_thread.messages:
                        delete_post(each_message.message_id)  # Delete thread posts
                    delete_thread(each_thread.thread_hash)  # Delete thread

                # Remove deleted message entries
                deleted_msgs = new_session.query(DeletedMessages).filter(
                    DeletedMessages.address_to == chan_address).all()
                for each_msg in deleted_msgs:
                    logger.info("DeletedMessages: Deleting entry: {}".format(each_msg.message_id))
                    new_session.delete(each_msg)

                if clear_mod_log:
                    # Delete mod log entries for address
                    mod_logs = new_session.query(ModLog).filter(
                        ModLog.board_address == chan_address).all()
                    for each_entry in mod_logs:
                        new_session.delete(each_entry)
                else:
                    user_name = get_logged_in_user_name()
                    admin_name = user_name if user_name else "LOCAL ADMIN"
                    add_mod_log_entry(
                        f"Left {chan.type} {chan.address}: /{chan.label}/ - {chan.description}",
                        board_address=chan_address,
                        user_from=admin_name)

                # Delete chan in BitChan database
                delete_chan(chan_address)

                daemon_com.delete_and_vacuum()
            else:
                logger.error("Could not leave chan in Bitmessage. Not deleting anything in BitChan.")
        except:
            logger.exception("Could not leave chan")
        finally:
            new_session.commit()
