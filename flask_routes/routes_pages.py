import base64
import logging

from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask.blueprints import Blueprint
from forms import forms_pages
from database.models import Pages
from bitchan_client import DaemonCom
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
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

    if "edit_id" in request.form:
        edit_id = request.form.get("edit_id")
    else:
        edit_id = None
        
    if request.method == 'POST':
        if delete_id:
            page_delete = Pages.query.filter(Pages.id == delete_id).first()
            page_delete.delete()
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
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("New user created")
        elif page_manage.edit_page.data:
            if not page_manage.slug.data.replace(" ", ""):
                status_msg['status_message'].append("URL Slug required")

            if not status_msg['status_message']:
                page_edit = Pages.query.filter(Pages.id == page_manage.edit_id.data).first()
                if page_edit:
                    page_edit.name = page_manage.name.data
                    page_edit.slug = page_manage.slug.data.replace(" ", "")
                    page_edit.html = page_manage.html.data
                    page_edit.save()
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Page edits saved")
        else:
            for each_input in request.form:
                if each_input.startswith("edit_"):
                    edit_id = each_input.split("_")[1]
                    break
                elif each_input.startswith("delete_"):
                    delete_id = each_input.split("_")[1]
                    break

    if edit_id:
        page_edit = Pages.query.filter(Pages.id == edit_id).first()
    else:
        page_edit = None

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/page_manage.html",
                           delete_id=delete_id,
                           edit_id=edit_id,
                           page_edit=page_edit,
                           page_manage=page_manage,
                           pages=Pages,
                           status_msg=status_msg)

@blueprint.route('/page/<slug>', methods=('GET', 'POST'))
@count_views
def page(slug):
    status_msg = {"status_message": []}

    this_page = Pages.query.filter(Pages.slug == slug).first()

    if not this_page:
        return "Not Found"

    return render_template("pages/page_show.html",
                           pages=Pages,
                           status_msg=status_msg,
                           this_page=this_page)
