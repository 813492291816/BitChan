# From https://raw.githubusercontent.com/Tethik/flask-session-captcha
import base64
import logging
from random import SystemRandom

from captcha.image import ImageCaptcha
from flask import session, request, Markup


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

    def generate(self, page_id):
        """
        Generates and returns a numeric captcha image in base64 format. 
        Saves the correct answer in `session['captcha_answer']`
        Use later as:

        src = captcha.generate()
        <img src="{{src}}">
        """                
        answer = self.rand.randrange(self.max)
        answer = str(answer).zfill(self.digits)        
        image_data = self.image_generator.generate(answer)
        base64_captcha = base64.b64encode(image_data.getvalue()).decode("ascii")
        logging.debug('Generated captcha with answer: ' + answer)

        # if page_id provided, permit saving multiple answers to session
        if page_id:
            if 'captcha_answers_id' not in session:
                session['captcha_answers_id'] = {}
            session['captcha_answers_id'][page_id] = answer
        else:
            session['captcha_answer'] = answer

        return base64_captcha

    def validate(self, form_key="captcha", page_id=None, value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        if page_id:
            session_values_id = session.get('captcha_answers_id', None)
            if session_values_id and page_id in session_values_id:
                session_value = session_values_id[page_id]
            else:
                return False
        else:
            session_value = session.get('captcha_answer', None)

        if not session_value:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        if page_id and 'captcha_answers_id' in session:
            session['captcha_answers_id'].pop(page_id, None)
        else:
            session['captcha_answer'] = None

        return value and value == session_value

    def get_answers(self):
        """
        Shortcut function that returns the currently saved answers.
        """
        return (session.get('captcha_answer', None),
                session.get('captcha_answers_id', None))
