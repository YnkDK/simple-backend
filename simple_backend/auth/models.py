# -*- coding: utf-8 -*-
# Import generic python stuff
from functools import wraps
import hashlib
import os
import random
from datetime import datetime
import time
# Import basic flask stuff
from flask import current_app, g, jsonify, request, make_response, Response
# Import database stuff
from flask.ext.security import SQLAlchemyUserDatastore
from sqlalchemy_utils import UUIDType
import uuid
from simple_backend.models import db, Session
# Import security stuff
import pbkdf2_ctypes
import flask_security
from flask.ext.login import AnonymousUserMixin
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

__author__ = 'mys'
__all__ = ['roles_logins', 'Login', 'Role', 'user_collection', 'auth_handler']

roles_logins = db.Table('roles_logins',
                        db.Column('user_id', UUIDType, db.ForeignKey('login.id')),
                        db.Column('role_id', UUIDType, db.ForeignKey('role.id')))


class Login(db.Model, flask_security.UserMixin):
    """
    Define the login/user model.

    Please note that the username is not stored in the database directly.
    This have (at least) the following consequences/advantages:
        1. The table reserves less space in the database
        2. The row of a specific login can be access on the primary key with Login.uuid(login)
        3. All usernames cannot be listed
    The last consequence might be unwanted, e.g. the admin cannot tell a user it's login without
    knowing the users login. A solution is to have a table (User) which stores everything else
    about a user, e.g. username, full name, email, phone number, address etc. with a reference
    to the login table.
    """

    # Define columns
    id = db.Column(UUIDType, primary_key=True)
    password = db.Column(db.Text(), nullable=False)
    active = db.Column(db.Boolean(), nullable=False, default=True)
    # Define relationships
    roles = db.relationship('Role', secondary=roles_logins,
                            backref=db.backref('logins', lazy='dynamic'))
    session = db.relationship('Session', uselist=False, backref='login')

    def __init__(self, **kwargs):
        super(Login, self).__init__()
        self.id = self.uuid(kwargs['login'])
        self.set_password(kwargs['password'])
        self.roles = kwargs['roles']
        if 'active' in kwargs:
            self.active = kwargs['active']

    def set_password(self, password):
        """
        Sets the encrypted password from the given plain-text password
        :param password: The plain-text password (must be of type str, not unicode!)
        :type password str
        """
        from simple_backend.auth.constants import PEPPERS
        iterations = current_app.config.get('PBKDF2_ITERATIONS', 2000)

        salt = os.urandom(16)
        # TODO: Support other algorithms than pbkdf2 and other than pbkdf2_sha512
        digest = pbkdf2_ctypes.pbkdf2_bin(
            data=random.choice(PEPPERS) + password + current_app.config['PROJECT_SALT'],
            salt=salt,
            iterations=iterations,
            hashfunc=hashlib.sha512
        )
        self.password = "${:s}${:d}${:s}${:s}".format(
            'pbkdf2_sha512',
            iterations,
            salt.encode('hex'),
            digest.encode('hex')
        )

    def get_id_unicode(self):
        """
        Returns the UUID in canonical form

        :return: The User ID
        :rtype unicode
        """
        return unicode(self.id)

    def verify_password(self, password):
        """
        Verifies a plain-text password with the hashed in the current user.

        :param password: A plain-text password (must be of type str, not unicode!)
        :type password str

        :return: True if the password was verified, false otherwise
        :rtype boolean
        """
        from auth.constants import PEPPERS
        # Get number of iterations
        # Get current salt and digest
        algorithm, iterations, salt, digest = self.password.split("$")[1:]
        salt = salt.decode('hex')
        digest = digest.decode('hex')
        iterations = int(iterations)
        if algorithm.startswith('pbkdf2'):
            algorithm, sha = algorithm.split("_")
            hash_func = getattr(hashlib, sha, 'sha512')
        else:
            raise ValueError("Unknown hash func")
        # Append the project salt to the end of the given user password
        password = password + current_app.config['PROJECT_SALT']
        # Shuffle the peppers to be faster on average
        random.shuffle(PEPPERS)
        for pepper in PEPPERS:
            # The password is now: pepper + password + project salt
            pwd = pepper + password
            if pbkdf2_ctypes.pbkdf2_bin(data=pwd, salt=salt, iterations=iterations, hashfunc=hash_func) == digest:
                # Bcrypt have now confirmed that the password was correct!
                return True
        # None of the peppers made the password correct, password incorrect!
        return False

    def generate_auth_token(self):
        """
        Generates a token storing the users UUID, which expires as fast as the
        fastest defined token time for all roles the user have. The user
        can access resources which requires login with this token as username
        and any password, e.g. token:42

        :return: The token
        :rtype unicode
        """
        # The token should expire as fast as possible
        token_time = min(self.roles, key=lambda x: x.token_time).token_time
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=token_time)
        return s.dumps({
            'id': self.get_id_unicode(),
            # Added to ensure (with high probability) unique tokens
            'r': os.urandom(8).encode('hex')
        })

    @staticmethod
    def verify_auth_token(token):
        """
        Verifies a token by:
            1. Checking if the token is expired
            2. Checking if the token is invalid
            3. Checking that the token is associated with the current session
            4. TODO: Renew token if need-be

        :param token: The token to be verified
        :return: None if token is invalid, otherwise the session attached to the user
        :rtype api.models.Session
        """
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        session = Session.query.filter_by(login_id=data['id']).first()
        if session is not None and session.login.active and session.token == token:
            return session
        return None

    @staticmethod
    def uuid(login):
        """
        :param login: The login to be logged in
        :type login basestring
        :return: Returns the UUID-5 generated from the e-mail
        :rtype uuid.UUID
        """
        return uuid.uuid5(uuid.NAMESPACE_OID, login)


class Role(db.Model, flask_security.RoleMixin):
    id = db.Column(UUIDType, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.String(255))
    token_time = db.Column(db.Integer, nullable=False, default=600)
    token_renew = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, name, description, token_time=None, token_renew=None):
        super(Role, self).__init__()
        self.id = self.uuid(name)
        self.name = name
        self.description = description
        if token_time:
            self.token_time = token_time
        if token_renew:
            self.token_renew = token_renew

    @staticmethod
    def uuid(name):
        return uuid.uuid5(uuid.NAMESPACE_OID, name)


user_collection = SQLAlchemyUserDatastore(db, Login, Role)


class Anonymous(AnonymousUserMixin):
    id = None
    roles = []


class AuthHandler(object):
    """
    An authentication class inspired by flask_httpauth by Miguel Grinberg
    (https://github.com/miguelgrinberg/Flask-HTTPAuth)

    This class is designed for RESTful Web Services. It is a token-based authentication system
    initiated by a POST request with username/password. Hereafter all subsequent calls can be
    verified by the given token, either from a cookie, header, query string or form field.

    Upon successful authentication (both username/password and token) the global variable flask.g
    is updated with:
        - g.session: The session ORM
        - g.login: The login ORM
    """

    def __init__(self):
        def default_unauthorized():
            """
            Returns a Response with error message and status set to fit
            the HTTP standard for unauthorized

            :return: An instance of Response with proper fields
            :rtype flask.Response
            """
            return jsonify({
                'message': 'Unauthorized',
                'status': 401
            })

        self.error_handler(default_unauthorized)

    def error_handler(self, f):
        """
        The function return either:
            - response_class: An instance of flask.response_class
            - str: a response object is created with the string as body
            - unicode: a response object is created with the string encoded to utf-8 as body
            - a WSGI function: the function is called as WSGI application and buffered as response object
            - tuple: A tuple in the form (response, status, headers) where response is any of the types
                     defined here, status is a string or an integer and headers is a list of a dictionary
                     with header values.
        :param f: A function returning one of the above
        :return: The decorated function, i.e. a response_class with status_code 401
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            res = f(*args, **kwargs)
            if not isinstance(res, Response):
                try:
                    res = make_response(res)
                except Exception:
                    res = make_response('unauthorized')
            res.status_code = 401
            return res

        self.auth_error_callback = decorated
        return decorated

    def username_password_required(self, f):
        """
        Validates the username/password given from either
            - POST/PUT form data
            - HTTP Basic Auth
        If the username/password combination was valid and the login is active,
        the session is updated along with flask.g.login and flask.g.session
        Otherwise the error_handler is issued

        :param f: A POST HTTP method
        :return: Either the original function or the error_handler
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == 'POST':
                form = request.form
                auth = request.authorization
                if 'username' in form and 'password' in form:
                    username = str(form['username'])
                    password = str(form['password'])
                elif auth:
                    username = str(auth.username)
                    password = str(auth.password)
                else:
                    return self.auth_error_callback()
            else:
                return self.auth_error_callback()
            # Get the user from data storage
            user = Login.query.filter_by(id=uuid.uuid5(uuid.NAMESPACE_OID, username)).first()
            if not user or not user.active:
                # -- OWASP: Use a cryptographically strong credential-specific salt
                # Make time-based attacks on a population intractable
                timeout = current_app.config['UNKNOWN_USER_TIMEOUT']
                # Add timeout +/- 10 percent
                time.sleep(timeout + random.uniform(-0.1, 0.1) * timeout)
                return self.auth_error_callback()
            elif not user.verify_password(password):
                # Either the user was not found, the password was incorrect or the user is inactive
                return self.auth_error_callback()
            # Success!
            g.login = user
            # Generate a token
            token = g.login.generate_auth_token()
            # Update or start the session
            session = Session.query.filter_by(login_id=g.login.id).first()
            if not session:
                session = Session(token=token, login_id=g.login.id)
                db.session.add(session)
            else:
                session.clear(token)
            g.session = session
            # Everything is now ready to be processed
            return f(*args, **kwargs)

        return decorated

    def token_required(self, f):
        """
        Fetches the token from either:
            - The header on key X-Auth-Token
            - The cookie on key: token
            - Query string/form data on key: token
        Then uses the Login-model to verify the auth token
        If the token was valid and the login is active, the session is updated
        along with flask.g.login and flask.g.session
        Otherwise the error_handler is issued
        :param f: Any GET, PUT, POST or DELETE HTTP method
        :return: Either the original function or the error_handler
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            if 'token' in request.values:
                token = request.values['token']
            elif 'X-Auth-Token' in request.headers:
                token = request.headers['X-Auth-Token']
            elif 'token' in request.cookies:
                token = request.cookies['token']
            else:
                return self.auth_error_callback()
            session = Login.verify_auth_token(token)
            if session and session.login.active:
                session.last_verified = datetime.utcnow()
                if any(role.token_renew for role in session.login.roles):
                    session.token = session.login.generate_auth_token()
                # Set the globals to be used in f
                g.login = session.login
                g.session = session
                # Everything went fine, return the original function
                return f(*args, **kwargs)
            # The session was not verified or the login is inactive
            return self.auth_error_callback()

        return decorated


auth_handler = AuthHandler()
