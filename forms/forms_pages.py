# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import SubmitField

logger = logging.getLogger("bitchan.forms_pages")


class PageManage(FlaskForm):
    name = StringField("Name")
    slug = StringField("URL Slug")
    html = StringField("HTML")

    edit_id = StringField("Page ID")
    edit_page = SubmitField("Save")
    add_page = SubmitField("Add Page")
