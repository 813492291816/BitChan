# From https://raw.githubusercontent.com/Tethik/flask-session-captcha
import base64
import logging
import time
from random import SystemRandom

from captcha.image import ImageCaptcha
from flask import Markup
from flask import request

from database.models import Captcha


class FlaskSessionCaptcha(object):
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Initialize the captcha extension to the given app object.
        """
        self.enabled = app.config.get("CAPTCHA_ENABLE", True)
        self.digits = app.config.get("CAPTCHA_LENGTH", 4)
        self.width = app.config.get("CAPTCHA_WIDTH", None)
        self.height = app.config.get("CAPTCHA_HEIGHT", None)
        self.fonts = app.config.get("CAPTCHA_FONTS", None)
        self.max = 10**self.digits

        xargs = {}
        if self.height:
            xargs['height'] = self.height
        if self.width:
            xargs['width'] = self.width
        if self.fonts:
            xargs['fonts'] = self.fonts

        self.image_generator = ImageCaptcha(**xargs)
        self.rand = SystemRandom()

        def _generate(page_id=None, img_id='captcha'):
            if not self.enabled:
                return ""
            base64_captcha = self.generate(page_id)
            return Markup("<img title='captcha' id='{}' src='data:image/png;base64, {}'>".format(
                img_id, base64_captcha))

        app.jinja_env.globals['captcha'] = _generate

        # Check for sessions that do not persist on the server.
        # Issue a warning because they are most likely open to replay attacks.
        # This addon is built upon flask-session.
        session_type = app.config.get('SESSION_TYPE', None)
        if session_type is None or session_type == "null":
            raise RuntimeWarning(
                "Flask-Sessionstore is not set to use a server persistent storage type."
                "This likely means that captchas are vulnerable to replay attacks.")
        elif session_type == "sqlalchemy":
            # I have to do this as of version 0.3.1 of flask-session if using
            # sqlalchemy as the session type in order to create the initial database.
            # Flask-sessionstore seems to have the same problem. 
            app.session_interface.db.create_all()

    def generate(self, captcha_id):
        """
        Generates and returns a numeric captcha image in base64 format.
        Use later as:

        src = captcha.generate(captcha_id)
        <img src="{{src}}">
        """                
        answer = self.rand.randrange(self.max)
        answer = str(answer).zfill(self.digits)        
        image_data = self.image_generator.generate(answer)
        base64_captcha = base64.b64encode(image_data.getvalue()).decode("ascii")
        logging.debug('Generated captcha with answer: ' + answer)

        captcha = Captcha.query.filter(Captcha.captcha_id == captcha_id).first()
        if not captcha:
            new_captcha = Captcha()
            new_captcha.captcha_id = captcha_id
            new_captcha.captcha_answer = answer
            new_captcha.timestamp_utc = time.time()
            new_captcha.save()

        return base64_captcha

    def validate(self, captcha_id, form_key="captcha", value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        captcha = Captcha.query.filter(Captcha.captcha_id == captcha_id).first()
        if not captcha:
            return False

        if not captcha.captcha_answer:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        captcha.delete()

        return value and value == captcha.captcha_answer
