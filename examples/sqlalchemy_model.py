from flask import Flask, request, redirect, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flaskext.auth import Auth, login_required, logout
from flaskext.auth.models.sa import get_user_class

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)
auth = Auth(app, login_url_name='index')

User = get_user_class(db.Model)

@login_required()
def admin():
    return 'Admin! Excellent!'

def index():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter(User.username==username).one()
        if user is not None:
            # Authenticate and log in!
            if user.authenticate(request.form['password']):
                return redirect(url_for('admin'))
        return 'Failure :('
    return '''
            <form method="POST">
                Username: <input type="text" name="username"/><br/>
                Password: <input type="password" name="password"/><br/>
                <input type="submit" value="Log in"/>
            </form>
        '''

def user_create():
    if request.method == 'POST':
        username = request.form['username']
        if User.query.filter(User.username==username).first():
            return 'User already exists.'
        password = request.form['password']
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return '''
            <form method="POST">
                Username: <input type="text" name="username"/><br/>
                Password: <input type="password" name="password"/><br/>
                <input type="submit" value="Create"/>
            </form>
        '''

def logout_view():
    user_data = logout()
    if user_data is None:
        return 'No user to log out.'
    return 'Logged out user {0}.'.format(user_data['username'])

# URLs
app.add_url_rule('/', 'index', index, methods=['GET', 'POST'])
app.add_url_rule('/admin/', 'admin', admin)
app.add_url_rule('/users/create/', 'user_create', user_create, methods=['GET', 'POST'])
app.add_url_rule('/logout/', 'logout', logout_view)

# Secret key needed to use sessions.
app.secret_key = 'N4BUdSXUzHxNoO8g'

if __name__ == '__main__':
    try:
        open('/tmp/flask_auth_test.db')
    except IOError:
        db.create_all()
    app.run(debug=True)
