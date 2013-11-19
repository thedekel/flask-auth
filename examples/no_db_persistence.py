from flask import Flask, request, g, redirect, url_for
app = Flask(__name__)

from flaskext.auth import Auth, AuthUser, login_required, logout
auth = Auth(app, login_url_name='index')

@app.before_request
def init_users():
    """
    Initializing users by hardcoding password. Another use case is to read
    usernames from an external file (like /etc/passwd).
    """
    admin = AuthUser(username='admin')
    # Setting and encrypting the hardcoded password.
    admin.set_and_encrypt_password('password', salt='123')
    # Persisting users for this request.
    g.users = {'admin': admin}

@login_required()
def admin():
    return 'Admin! Excellent!'

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

def logout_view():
    user_data = logout()
    if user_data is None:
        return 'No user to log out.'
    return 'Logged out user {0}.'.format(user_data['username'])

# URLs
app.add_url_rule('/', 'index', index, methods=['GET', 'POST'])
app.add_url_rule('/admin/', 'admin', admin)
app.add_url_rule('/logout/', 'logout', logout_view)

# Secret key needed to use sessions.
app.secret_key = 'N4BUdSXUzHxNoO8g'

if __name__ == '__main__':
    app.run(debug=True)
