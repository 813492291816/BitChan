# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import FileField
from wtforms import IntegerField
from wtforms import MultipleFileField
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField

logger = logging.getLogger("bitchan.forms_admin")


class KioskUsers(FlaskForm):
    name = StringField("Name")
    is_admin = BooleanField("Is Admin")
    is_janitor = BooleanField("Is Janitor")
    is_board_list_admin = BooleanField("Is Board/List Admin")
    admin_boards = StringField("Admin Boards/Lists")
    can_post = BooleanField("Can Post")
    single_session = BooleanField("Single Session")

    new_password = StringField("New Password")
    retype_password = StringField("Retype")
    require_change_pw = BooleanField("Require Changing on First Use")

    edit_id = StringField("User ID")
    edit_user = SubmitField("Save")
    add_user = SubmitField("Add User")


class KioskChangePW(FlaskForm):
    current_password = StringField("Current Password")
    new_password = StringField("New Password")
    new_password_repeat = StringField("New Password Repeat")
    new_pw = SubmitField("Submit")
