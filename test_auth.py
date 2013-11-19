import unittest, hashlib
from flask import Flask, session
from flaskext.auth import Auth, AuthUser, login, logout, encrypt, Role, \
    get_current_user_data, Permission, has_permission, login_required, \
    permission_required
from flaskext.auth.auth import SESSION_USER_KEY, SESSION_LOGIN_KEY


class EncryptionTestCase(unittest.TestCase):
    PASSWORD = 'password'
    SALT = '123'
    HASH_ALGORITHM = hashlib.sha1
    PRECOMPUTED_RESULT = 'cbfdac6008f9cab4083784cbd1874f76618d2a97'

    def setUp(self):
        app = Flask(__name__)
        auth = Auth(app)
        self.app = app
        auth.hash_algorithm = self.HASH_ALGORITHM
        user = AuthUser(username='user')
        self.user = user

    def test_encryption(self):
        assert encrypt(password=self.PASSWORD, salt=self.SALT,
                       hash_algorithm=self.HASH_ALGORITHM) == self.PRECOMPUTED_RESULT

    def test_set_and_encrypt_password(self):
        with self.app.test_request_context():
            self.user.set_and_encrypt_password(self.PASSWORD, self.SALT)
        assert self.user.password == self.PRECOMPUTED_RESULT
        assert self.user.salt == self.SALT


class LoginTestCase(unittest.TestCase):
    PASSWORD = 'password'

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = 'N4buDSXfaHx2oO8g'
        auth = Auth(app)
        auth.hash_algorithm = hashlib.sha1
        user = AuthUser(username='user')
        with app.test_request_context():
            user.set_and_encrypt_password(self.PASSWORD)
        self.app = app
        self.user = user

    def tearDown(self):
        with self.app.test_request_context():
            logout()

    def test_login(self):
        with self.app.test_request_context():
            login(self.user)
            assert session[SESSION_USER_KEY] is not None
            assert session.get(SESSION_LOGIN_KEY)

    def test_current_user(self):
        with self.app.test_request_context():
            login(self.user)
            assert get_current_user_data() == self.user.__dict__
            assert AuthUser.load_current_user() == self.user

    def test_logout(self):
        with self.app.test_request_context():
            login(self.user)
            user_data = logout()
            assert user_data['username'] == self.user.username
            assert session.get(SESSION_USER_KEY) is None
            assert session.get(SESSION_LOGIN_KEY) is None

    def test_user_expiration(self):
        import time
        with self.app.test_request_context():
            self.app.auth.user_timeout = 0.01
            login(self.user)
            time.sleep(0.02)
            assert get_current_user_data() is None
            assert AuthUser.load_current_user() is None

    def test_user_expiration_override(self):
        import time
        with self.app.test_request_context():
            self.app.auth.user_timeout = 0.01
            login(self.user)
            time.sleep(0.02)
            assert AuthUser.load_current_user(apply_timeout=False) == self.user

    def test_authenticate(self):
        with self.app.test_request_context():
            assert self.user.authenticate(self.PASSWORD) is True
            assert self.user.is_logged_in() is True
            assert AuthUser.load_current_user() == self.user

    def test_authenticate_fail(self):
        with self.app.test_request_context():
            assert self.user.authenticate('bla') is False
            assert self.user.is_logged_in() is False


class PermissionTestCase(unittest.TestCase):
    post_view = Permission('post', 'view')
    post_update = Permission('post', 'update')
    ROLES = {'testuser': Role('testuser', [post_view])}

    def setUp(self):
        app = Flask(__name__)
        auth = Auth(app)
        self.app = app

        def load_role(role_name):
            return self.ROLES.get(role_name)

        auth.load_role = load_role
        user = AuthUser(username='user')
        user.role = 'testuser'
        self.user = user

    def tearDown(self):
        pass

    def test_has_permission(self):
        with self.app.test_request_context():
            assert has_permission(self.user.role, 'post', 'view') is True
            assert has_permission(self.user.role, 'post', 'update') is False
            assert has_permission(self.user.role, 'user', 'view') is False
            assert has_permission(self.user.role, 'user', 'create') is False

    def test_permission_equals(self):
        assert self.post_view == Permission('post', 'view')
        assert self.post_update != self.post_view


class RequestTestCase(unittest.TestCase):

    def setUp(self):
        app = Flask(__name__)
        app.secret_key = 'N4buDSXfaHx2oO8g'
        self.app = app
        auth = Auth(app)

        @login_required
        def needs_login():
            return 'needs_login'

        app.add_url_rule('/needs_login/', 'needs_login', needs_login)

        @permission_required(resource='post', action='view')
        def post_view():
            return 'needs_post_view'
        app.add_url_rule('/post_view/', 'post_view', post_view)

        @app.route('/login_view/')
        def login_view():
            return 'login_view'

        user = AuthUser(username='user')
        user.role = 'testuser'
        testuser_role = Role('testuser', [Permission('post', 'view')])
        auth.load_role = lambda _: testuser_role
        self.user = user

    def tearDown(self):
        with self.app.test_request_context():
            logout()

    def test_default_not_logged_in_callback(self):
        with self.app.test_request_context():
            with self.app.test_client() as client:
                assert client.get('/needs_login/').status_code == 401

    def test_permission_required_no_login(self):
        with self.app.test_request_context():
            with self.app.test_client() as client:
                assert client.get('/post_view/').status_code == 401

suite = unittest.TestLoader().discover(start_dir='.')
if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
