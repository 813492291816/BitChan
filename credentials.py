from utils.login import Credentials

# Credentials are only used if Kiosk mode is enabled in config.py
# If enabling kiosk mode, change the default password
# Notes:
#   It is forbidden to log in with the default password "DEFAULT_PASSWORD_CHANGE_ME"
#   IDs and Passwords must be unique
credentials = Credentials()

# Example users
credentials.add_user(
    id_="Admin_01",
    password="DEFAULT_PASSWORD_CHANGE_ME",  # Default password is prohibited. Must be changed to something else to work.
    single_session=False, global_admin=True, can_post=True, janitor=False,
    board_list_admin=False, admin_boards=[])
# credentials.add_user(
#     id_="Janitor_no_01",
#     password="JANITOR_MULTI_NO",
#     single_session=True, global_admin=False, can_post=True, janitor=True,
#     board_list_admin=False, admin_boards=[])
# credentials.add_user(
#     id_="Board_admin_post_yes_multi_no_01",
#     password="BOARD_ADMIN_MULTI_NO",
#     single_session=True, global_admin=False, can_post=True,
#     board_list_admin=False,
#     admin_boards=[
#         "BM-2cR1Ui3rnydtzx96JuesjmAevaA79GN8YV",
#         "BM-2cE3zh3Wnpdfz206Auew2mMevaUW6svsqp"
#     ])
# credentials.add_user(
#     id_="Guest_post_yes_multi_no_01",
#     password="GUEST_POST_YES_MULTI_NO",
#     single_session=True, global_admin=False, can_post=True,
#     board_list_admin=False, admin_boards=[])
# credentials.add_user(
#     id_="Guest_post_yes_multi_yes_01",
#     password="GUEST_POST_YES_MULTI_YES",
#     single_session=False, global_admin=False, can_post=True,
#     board_list_admin=False, admin_boards=[])
# credentials.add_user(
#     id_="Guest_post_no_multi_no_01",
#     password="GUEST_POST_NO_MULTI_NO",
#     single_session=True, global_admin=False, can_post=False,
#     board_list_admin=False, admin_boards=[])
# credentials.add_user(
#     id_="Guest_post_no_multi_yes_01",
#     password="GUEST_POST_NO_MULTI_YES",
#     single_session=False, global_admin=False, can_post=False,
#     board_list_admin=False, admin_boards=[])
