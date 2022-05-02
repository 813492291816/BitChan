import logging

logger = logging.getLogger('bitchan.login')


class Credentials:
    def __init__(self, ):
        self.users = []

    def add_user(self, id_, password,
                 single_session=False,
                 global_admin=False,
                 can_post=False,
                 janitor=False,
                 board_list_admin=False,
                 admin_boards=False):
        for each_user in self.users:
            if password == each_user["password"]:
                logger.error("Password must be unique")
                return
            if id_ == each_user["id"]:
                logger.error("ID must be unique")
                return
        self.users.append({
            "id": id_,
            "password": password,
            "single_session": single_session,
            "global_admin": global_admin,
            "can_post": can_post,
            "janitor": janitor,
            "board_list_admin": board_list_admin,
            "admin_boards": admin_boards
        })

    def get_user_by_id(self, id_):
        for each_user in self.users:
            if each_user["id"] == id_:
                return each_user

    def get_user_by_password(self, password):
        for each_user in self.users:
            if each_user["password"] == password:
                return each_user
