import base64
import logging
import os

from flask import abort
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask.blueprints import Blueprint

from bitchan_client import DaemonCom
from config import CODE_DIR
from config import INSTALL_DIR
from database.models import Pages
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_pages
from utils.files import delete_file
from utils.routes import allowed_access
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_pages')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_pages',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    if not is_verified():
        full_path_b64 = "0"
        if request.method == "GET":
            if request.url:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.url.encode()).decode()
            elif request.referrer:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.referrer.encode()).decode()
        elif request.method == "POST":
            if request.referrer:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.referrer.encode()).decode()
        return redirect(url_for('routes_verify.verify_wait',
                                full_path_b64=full_path_b64))
    return None


@blueprint.route('/manage_pages', methods=('GET', 'POST'))
@count_views
def manage_pages():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    page_manage = forms_pages.PageManage()
    status_msg = {"status_message": []}
    delete_id = None

    for each_id in request.form:
        if each_id.startswith("delete_"):
            delete_id = each_id.split("_")[1]
            break
        
    if request.method == 'POST':
        if delete_id:
            page_delete = Pages.query.filter(Pages.id == delete_id).first()
            page_id = page_delete.id
            page_delete.delete()

            dir_save = create_page_symlink()
            path_page = os.path.join(dir_save, f"{page_id}.html")
            if os.path.isfile(path_page):
                delete_file(path_page)

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append("Page deleted")

        elif page_manage.add_page.data:
            if not page_manage.slug.data.replace(" ", ""):
                status_msg['status_message'].append("URL Slug required")

            if not status_msg['status_message']:
                new_page = Pages()
                new_page.name = page_manage.name.data
                new_page.slug = page_manage.slug.data.replace(" ", "")
                new_page.html = page_manage.html.data
                new_page.save()

                save_template_page(new_page.id, force=True)

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("New user created")

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/page_manage.html",
                           status_msg=status_msg)


@blueprint.route('/edit_page/<page_id>', methods=('GET', 'POST'))
@count_views
def edit_page(page_id):
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    page_manage = forms_pages.PageManage()
    status_msg = {"status_message": []}

    if request.method == 'POST':
        if page_manage.edit_page.data:
            if not page_manage.slug.data.replace(" ", ""):
                status_msg['status_message'].append("URL Slug required")

            if not status_msg['status_message']:
                page_edit = Pages.query.filter(Pages.id == page_id).first()
                if page_edit:
                    page_edit.name = page_manage.name.data
                    page_edit.slug = page_manage.slug.data.replace(" ", "")
                    page_edit.html = page_manage.html.data
                    page_edit.save()

                    save_template_page(page_edit.id, force=True)

                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(f"Page edits saved")

    page_edit = Pages.query.filter(Pages.id == page_id).first()

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/page_edit.html",
                           page_edit=page_edit,
                           status_msg=status_msg)


@blueprint.route('/page/<slug>', methods=('GET', 'POST'))
@count_views
def page(slug):
    status_msg = {"status_message": []}

    this_page = Pages.query.filter(Pages.slug == slug).first()

    if not this_page:
        abort(404)

    save_template_page(this_page.id)

    return render_template(f"user_pages/{this_page.id}.html",
                           status_msg=status_msg)


def save_template_page(page_id, force=False):
    this_page = Pages.query.filter(Pages.id == page_id).first()

    if not this_page:
        return

    dir_save = create_page_symlink()
    path_page = os.path.join(dir_save, f"{this_page.id}.html")

    if not os.path.isdir(dir_save):
        os.mkdir(dir_save)
    if force or not os.path.isfile(path_page):
        with open(path_page, "w") as f:
            f.write(f"""{{% extends "layout.html" %}}

{{% block title %}}{this_page.name} - {{% endblock %}}

{{% block body %}}
    {{% include '/elements/banner.html' %}}
    <br/>

    {{% if status_msg["status_message"] %}}
        {{% include '/elements/status.html' %}}
    {{% endif %}}
    
    {{% if global_admin %}}
    <div style="text-align: center; padding-bottom: 1em">
        <a class="link" href="/edit_page/{this_page.id}">Edit Page</a>
    </div>
    {{% endif %}}

    {this_page.html}

    {{% include '/elements/display_boards.html' %}}
    {{% include '/elements/display_lists.html' %}}
    {{% include '/elements/display_pages.html' %}}
    <div style="padding-top: 1em"></div>
{{% endblock %}}""")


def create_page_symlink():
    dir_templates = os.path.join(CODE_DIR, "templates")
    dir_template_pages = os.path.join(dir_templates, "user_pages")
    dir_save = os.path.join(INSTALL_DIR, "user_pages")
    if not os.path.islink(dir_template_pages):
        os.symlink(dir_save, dir_template_pages)

    return dir_save
