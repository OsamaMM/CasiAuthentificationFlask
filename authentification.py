from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from flask_oauthlib.client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
import os

# initialization
app = Flask(__name__, static_url_path = "", static_folder = "templates")
app.debug = True
app.config['SECRET_KEY'] = 'casi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
oauth = OAuth(app)

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

linkedin = oauth.remote_app(
    'linkedin',
    consumer_key='7740w9l26gepxi',
    consumer_secret='4wHCQUOWntpNzOvC',
    request_token_params={
        'scope': 'r_basicprofile',
        'state': 'RandomString',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
)

class User(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(32), primary_key=True)
    first_name = db.Column(db.String(32))
    last_name = db.Column(db.String(32))
    password_hash = db.Column(db.Text)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


@auth.verify_password
def verify_password(email, password):
    # try to authenticate with username/password
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

@app.route('/')
def index():
    return render_template('index.html',)


@app.route('/linkedinLogin')
def linkedin_login():
    return linkedin.authorize(callback=url_for('authorized', _external=True))


@app.route('/signup')
def signup():
    return render_template('signup.html',)


@app.route('/directLogin')
def direct_login():
    return render_template('login.html',)

@app.route('/successfulLogin', methods=['POST'])
def successful_login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        return redirect(url_for('signup'))
    return redirect("http://prodageo.insa-rouen.fr/")

@app.route('/successfulSignup', methods=['POST'])
def successful_signup():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    user = User(email=email, first_name=first_name, last_name=last_name)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return redirect("http://prodageo.insa-rouen.fr/")

@app.route('/logout')
def logout():
    session.pop('linkedin_token', None)
    return redirect(url_for('index'))


@app.route('/login/authorized')
def authorized():
    resp = linkedin.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['linkedin_token'] = (resp['access_token'], '')
    return redirect("http://prodageo.insa-rouen.fr/")


@linkedin.tokengetter
def get_linkedin_oauth_token():
    return session.get('linkedin_token')


def change_linkedin_query(uri, headers, body):
    auth = headers.pop('Authorization')
    headers['x-li-format'] = 'json'
    if auth:
        auth = auth.replace('Bearer', '').strip()
        if '?' in uri:
            uri += '&oauth2_access_token=' + auth
        else:
            uri += '?oauth2_access_token=' + auth
    return uri, headers, body

linkedin.pre_request = change_linkedin_query


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run()
