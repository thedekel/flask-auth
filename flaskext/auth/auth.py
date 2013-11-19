"""
Base module of the extension. Contains basic functions, the Auth object and the
AuthUser base class.
"""

import os
import hashlib
import datetime
from flask import session, abort, current_app

app.auth.hash_algorithm = lambda to_encrypt: original_algorithm(to_encrypt.encode('utf-8'))
DEFAULT_HASH_ALGORITHM = hashlib.sha1

DEFAULT_USER_TIMEOUT = 3600

SESSION_USER_KEY = 'auth_user'
SESSION_LOGIN_KEY = 'auth_login'


def _default_not_authorized():
    return abort(401)


class Auth(object):
    """
    Extension initialization object containing settings for the extension.

    :attr not_logged_in_callback: Function to call when a user accesses a page
    without being logged in. Normally used to redirect to the login page.
    If a login_url_name is provided, it will by default redirect to that
    url. Otherwise, the default is abort(401).
    :attr not_permitted_callback: Function to call when a user tries to access
    a page for which he doesn't have the permission. Default: abort(401).
    :attr hash_algorithm: Algorithm from the hashlib library used for password
    encryption. Default: sha1.
    :attr user_timeout: Timeout (in seconds) after which the sesion of the user
    expires. Default: 3600. A timeout of 0 means it will never expire.
    :attr load_role: Function to load a role. Is called with user.role as only
    parameter.
    """

    def __init__(self, app=None):
        self.not_logged_in_callback = _default_not_authorized
        self.not_permitted_callback = _default_not_authorized
        original_algorithm = DEFAULT_HASH_ALGORITHM
        self.hash_algorithm = lambda to_encrypt: original_algorithm(to_encrypt.encode('utf-8'))
        self.user_timeout = DEFAULT_USER_TIMEOUT
        self.load_role = lambda _: None
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.auth = self

    def not_logged_in_handler(self, func):
        self.not_logged_in_callback = func
        return func


class AuthUser(object):
    """
    Baseclass for a user model. Contains a few convenience methods.

    :attr username: Username of the user.
    :attr password: Password of the user. The :meth`AuthUser.set_and_encrypt_password`
    method sets and encrypts the password.
    :attr salt: Salt used for the encrytion of the password.
    :attr role: Role of this user.
    """

    role = None

    def __init__(self, username=None, password=None, salt=None, role=None):
        self.username = username
        # Storing password unmodified. Encryption of the password should
        # happen explicitly.
        self.password = password
        self.salt = salt
        self.role = role

    def set_and_encrypt_password(self, password, salt=None):
        """
        Encrypts and sets the password. If no salt is provided, a new
        one is generated.
        """
        self.salt = salt if salt is not None else os.urandom(12)
        self.password = encrypt(password, self.salt)

    def authenticate(self, password):
        """
        Attempts to verify the password and log the user in. Returns true if
        succesful.
        """
        if self.password == encrypt(password, self.salt):
            login(self)
            return True
        return False

    def __eq__(self, other):
        return self.username == getattr(other, 'username', None)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getstate__(self):
        return self.__dict__

    @classmethod
    def load_current_user(cls, apply_timeout=True):
        """
        Load current user based on the result of get_current_user_data().
        """
        data = get_current_user_data(apply_timeout)
        if not data:
            return None
        user = cls()
        user.__dict__ = data
        return user

    def is_logged_in(self):
        user_data = get_current_user_data()
        return user_data is not None and user_data.get('username') == self.username


def encrypt(password, salt=None, hash_algorithm=None):
    """Encrypts a password based on the hashing algorithm."""
    to_encrypt = password
    if salt is not None:
        to_encrypt += salt
    if hash_algorithm is not None:
        return hash_algorithm(to_encrypt).hexdigest()
    return current_app.auth.hash_algorithm(to_encrypt).hexdigest()


def login(user):
    """
    Logs the user in. Note that NO AUTHENTICATION is done by this function. If
    you want to authenticate a user, use the :meth`AuthUser.authenticate` method.
    """
    session[SESSION_USER_KEY] = user.__getstate__()
    session[SESSION_LOGIN_KEY] = datetime.datetime.utcnow()


def logout():
    """Logs the currently logged in user out and returns the user data."""
    session.pop(SESSION_LOGIN_KEY, None)
    return session.pop(SESSION_USER_KEY, None)


def get_current_user_data(apply_timeout=True):
    """
    Returns the data of the current user (user.__dict__) if there is a
    current user and he didn't time out yet. If timeout should be ignored,
    provide apply_timeout=False.
    """
    user_data = session.get(SESSION_USER_KEY, None)
    if user_data is None:
        return None
    if not apply_timeout:
        return user_data
    login_datetime = session[SESSION_LOGIN_KEY]
    now = datetime.datetime.utcnow()
    user_timeout = current_app.auth.user_timeout
    if user_timeout > 0 and now - login_datetime > \
       datetime.timedelta(seconds=user_timeout):
        logout()
        return None
    return user_data


def not_logged_in(*args, **kwargs):
    """
    Executes not logged in callback. Not for external use.
    """
    return current_app.auth.not_logged_in_callback(*args, **kwargs)


def login_required(func):
    """Decorator for views that require login."""
    def decorator(*args, **kwargs):
        if get_current_user_data() is None:
            return not_logged_in(*args, **kwargs)
        return func(*args, **kwargs)
    return decorator
