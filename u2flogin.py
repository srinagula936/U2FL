# -*- coding: utf-8 -*-

import time
import logging
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash

from u2fval_client.client import Client
from u2fval_client.auth import ApiToken
from u2fval_client import exc

# U2FVAL server settings
U2FVAL_HOST = 'https://u2fval.appspot.com/api'
try:
    with open('u2fval_api_token', 'r') as f:
        U2FVAL_API_TOKEN = f.read().strip()
except IOError:
    print 'No U2FVAL API key found.'

# U2FVAL client
u2fval = Client(U2FVAL_HOST, ApiToken(U2FVAL_API_TOKEN))

# configuration
DATABASE = 'C:\Users\snagula\AppData\Local\Temp\U2F_Login\u2flogin.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


def get_current_user():
    """Get the currently logged in user ID, as a string.
    If the user is not logged in, respond with 401."""
    if 'user_id' not in session:
        abort(401)
    return str(session['user_id'])


@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def init_db():
    """Creates the database tables."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.route('/')
def timeline():
    if not g.user:
        return redirect(url_for('index'))
    return render_template('layout.html')

@app.route('/index')
def index():
    return render_template('layout.html')

@app.route('/home')
def home():
    logging.debug('You are inside home')
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        print "User Logged in"
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            try:
                session['u2f_user_id'] = user['user_id']
                auth_req = u2fval.auth_begin(str(user['user_id']))
                return render_template('u2f_auth.html', auth_req=auth_req)
            except exc.NoEligableDevicesException as e:
                if not e.has_devices():
                    flash('You were logged in without U2F')
                    print "You were logged in without U2F"
                    session['user_id'] = user['user_id']
                    return redirect(url_for('home'))
                error = e.message
    return render_template('layout.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('''insert into user (
              username, email, pw_hash) values (?, ?, ?)''',
              [request.form['username'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/security')
def security():
    """Security (U2F) options."""
    devices = u2fval.list_devices(get_current_user())
    return render_template('security.html', devices=devices)


@app.route('/u2f_register', methods=['POST'])
def u2f_register():
    """Register a U2F device"""
    reg_req = u2fval.register_begin(get_current_user())
    return render_template('u2f_add.html',
                           name=request.form['name'],
                           reg_req=reg_req)

@app.route('/u2f_register_complete', methods=['POST'])
def u2f_register_complete():
    u2fval.register_complete(get_current_user(), request.form['u2f_data'],
                             {'name': request.form['name']})
    return redirect(url_for('security'))

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))

if __name__ == '__main__':
    import sys
    if '--init-db' in sys.argv:
        init_db()
        print "Database initialized!"
        sys.exit(0)

    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) # channel encryption protocol
    context.load_cert_chain('server.crt', 'server.key')

    app.run(ssl_context=context)
