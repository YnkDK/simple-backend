# -*- coding: utf-8 -*-
import os
import random
from datetime import datetime
import uuid

import bcrypt
from flask.ext.security import SQLAlchemyUserDatastore
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
import flask_security
from flask.ext.login import AnonymousUserMixin
from flask import current_app, g, jsonify
from flask.ext.httpauth import HTTPBasicAuth
from sqlalchemy_utils import UUIDType

from api.models import db, Session

__author__ = 'mys'

roles_logins = db.Table('roles_logins',
                        db.Column('user_id', UUIDType, db.ForeignKey('login.id')),
                        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Login(db.Model, flask_security.UserMixin):
    # Define columns
    id = db.Column(UUIDType, primary_key=True)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), nullable=False, default=True)
    # Define relationships
    roles = db.relationship('Role', secondary=roles_logins,
                            backref=db.backref('logins', lazy='dynamic'))
    session = db.relationship('Session', uselist=False, backref='login')

    def __init__(self, **kwargs):
        super(Login, self).__init__()
        self.id = self.uuid(kwargs['email'])
        self.password = bcrypt.hashpw(
            self.get_random_pepper() + kwargs['password'] + current_app.config['PROJECT_SALT'],
            # Generate user specific salt
            bcrypt.gensalt(6))
        self.roles = kwargs['roles']

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

        :param password: A plain-text password
        :return: True if the password was verified, false otherwise
        """
        # TODO: Why is the needed? Shouldn't SQLAlchemy take care of this?!
        self.password = self.password.encode('utf8')
        # Append the project salt to the end of the given user password
        password = password + current_app.config['PROJECT_SALT']
        # Prepare the peppers [1..255]. NB: \x00 is not allowed in bcrypt
        PEPPERS = range(1, 256)
        # Shuffle the peppers to be faster on average
        random.shuffle(PEPPERS)
        for pepper in PEPPERS:
            # The password is npw: pepper + password + project salt
            pwd = chr(pepper) + password
            if bcrypt.hashpw(pwd, self.password) == self.password:
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
    def uuid(email):
        """
        :param email: The email/username to be logged in
        :type email basestring
        :return: Returns the UUID-5 generated from the e-mail
        :rtype uuid.UUID
        """
        return uuid.uuid5(uuid.NAMESPACE_OID, email)

    @staticmethod
    def get_random_pepper():
        """
        Generates a random byte between 1 and 255 (both included) using the
        os.urandom method

        :return: A single byte
        """
        while True:
            pepper = os.urandom(1)
            if pepper != '\x00':
                return pepper


class Role(db.Model, flask_security.RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)
    description = db.Column(db.String(255))
    token_time = db.Column(db.Integer, nullable=False, default=600)
    token_renew = db.Column(db.Boolean, nullable=False, default=False)


user_collection = SQLAlchemyUserDatastore(db, Login, Role)


class Anonymous(AnonymousUserMixin):
    id = None
    roles = []


http_basic_auth = HTTPBasicAuth()


@http_basic_auth.error_handler
def unauthorized():
    # do stuff
    json = jsonify({
        'message': 'Unauthorized',
        'status': 401
    })
    json.status_code = 401
    return json


@http_basic_auth.verify_password
def verify_password(email_or_token, password):
    # first try to authenticate by token
    session = Login.verify_auth_token(email_or_token)
    if session and session.login.active:
        session.last_verified = datetime.utcnow()
        if any(role.token_renew for role in session.login.roles):
            session.token = session.login.generate_auth_token()
        db.session.commit()
        g.login = session.login
        g.session = session
        return True
    # try to authenticate with username/password
    user = Login.query.filter_by(id=uuid.uuid5(uuid.NAMESPACE_OID, email_or_token)).first()
    if not user or not user.verify_password(password) or not user.active:
        return False
    g.login = user
    return True
