Quickstart
==========

Flask-Auth is easy to use and saves you all the tedious work of rolling your own
authentication system. It's pretty much plug-and-play in most cases, so you can
be up and running in minutes.

Initializing the extension
--------------------------

You initialize the extension like so:

::

    app = Flask(__name__)
    from flaskext.auth import Auth
    auth = Auth(app)

Et voila, you're ready to go! The Auth object you just created allows you to
customize a number of settings (such as default callback when logging in is
required and the user session timeout), but the default settings should be fine
for most cases.

Static users
------------

What you need to do now is think about where your users will be defined and/or
stored. In this quickstart, we'll walk through the use case of having a static
user that is defined in the code. This can be easily adapted to read users from
a file (such as ``/etc/passwd``).

So, with the auth app initialized as above, we'll write a function that
initializes the users, decorated with the ``before_request`` decorator from
Flask to make sure the users are always initialized. Note that for illustration
purposes, the password is set here in plain text; what you would usually do in
this use case is precompute the hash of the password and assign this directly to
the ``password`` attribute of the user.

::

    @app.before_request
    def init_users():
        admin = AuthUser(username='admin')
        admin.set_and_encrypt_password('password')
        g.users = {'admin': admin}

Now we can write a view that allows the user to log in.

::

    def index():
        if request.method == 'POST':
            username = request.form['username']
            if username in g.users:
                # Authenticate and log in!
                if g.users[username].authenticate(request.form['password']):
                    return redirect(url_for('admin'))
            return 'Failure :('
        return '''
                <form method="POST">
                    Username: <input type="text" name="username"/><br/>
                    Password: <input type="password" name="password"/><br/>
                    <input type="submit" value="Log in"/>
                </form>
            '''

The most important part of the above code is the ``authenticate()`` call on the
user. This method gets as argument the password of the user and, if this is
correct, will log the user in. The ``login()`` function used in this method can
also be called directly to log a user in if you want to do authentication in
another way.

All that's left now is to create a view that is only accessible for logged in
users.

::

    @login_required()
    def admin():
        return 'Admin! Excellent!'

To wrap things up:

::

    app.add_url_rule('/', 'index', index, methods=['GET', 'POST'])
    app.add_url_rule('/admin/', 'admin', admin)
    app.secret_key = 'N4BUdSXUzHxNoO8g'

    if __name__ == '__main__':
        app.run(debug=True)

And you're done! This example is fully worked out (including a couple extra bells and whistles) in ``examples/no_persistence.py``.

User persistence
----------------

The most common option however for managing users is to persist them to a
database, in which case you will most probably use an ORM. The AuthUser base
class provides a couple of convenience functions so it is recommended to use
this as a base class or mixin.  If you're using Google App Engine, a
plug-and-play model is defined in flaskext.auth.gae.User, which can of course be
extended. If you use SQLAlchemy, you can follow the implementation in
``examples/sqlalchemy_model.py``.

Roles and permissions
---------------------

If you want to differentiate between users and do specific permission checking
on views, a permission model based on roles can be defined. It works very
straightforward: A user has a role (like "admin") and a role has a set of
permissions, with a permission being an action that is applied on a resource.
Examples of resources are "newsitem", "user", "ticket", "product", but also
"newsitem.comment", "user.role", etc. Examples of actions are "create", "read",
"list", "download", etc.

To get the above working, you first have to define your roles and the
permissions they have in some way. Personally I am of the opinion that you
shouldn't store roles and the permissions they have in a database, as it is part
of the configuration of your application and as such should be stored in a
versioned repository. In this extension, you can do this by defining instances
of the Role and Permission objects in your settings file. The only thing that
really has to be stored is the role of a user, which can be done by simply
storing the name of the role with the user. There are however of course valid
use cases in which you would want to store it in the database anyway, which is
fairly simple to do by using the Role and Permission classes as mixins for your
ORM models.

In both of the above cases, you can tie everything together by providing a
callback to load a role and attach this to the ``load_role`` attribute of the
auth object we created when initializing the extension. This callback is called
with as argument the name of a role and is supposed to return a Role object
(containing the role name and a list of permissions). In code, the above could
result in something like this:

::

	from flaskext.auth.permissions import Permission, Role

	user_create = Permission('user', 'create')
	user_view = Permission('user', 'view')

	roles = {
		'admin': Role('admin', [user_create, user_view]),
		'userview': Role('userview', [user_view]),
	}

	def load_role(role_name):
		return roles.get(role_name)

	auth.load_role = load_role

The above is worked out in ``examples/permissions.py``.
