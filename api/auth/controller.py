#!/usr/bin/python
# -*- coding: utf-8 -*-

import flask
import flask_restful
import flask_restful.reqparse

from api.auth.constants import MARSHAL_GET, MARSHAL_POST
from api.auth.models import auth_handler
from api.models import db, Session
from api.util import roles_accepted, tokenify_output

__author__ = 'mys'

bp = flask.Blueprint('api_v1', __name__)
api = flask_restful.Api(bp)


class Auth(flask_restful.Resource):
    @auth_handler.token_required  # First ensure that the user is logged in
    @roles_accepted('admin')  # Then check that the user have a correct role
    @tokenify_output(MARSHAL_GET)  # Lastly,set the basic marshals, i.e. message, status and token
    def get(self):
        return {
            'id': flask.g.login.get_id_unicode(),
        }

    @auth_handler.username_password_required
    @tokenify_output(MARSHAL_POST)
    def post(self):
        # Get the token
        token = flask.g.login.generate_auth_token()

        # Update the session
        session = Session.query.filter_by(login_id=flask.g.login.id).first()
        if not session:
            session = Session(token=token, login_id=flask.g.login.id)
            db.session.add(session)
        else:
            session.clear(token)
        db.session.commit()

        return {
            'status': 200,
            'message': 'OK',
            'token': token
        }

    @auth_handler.token_required
    @tokenify_output(MARSHAL_GET)
    def put(self):
        # TODO: Admin should be able to change other users
        # TODO: Admin should be able to change roles for other users
        args = self.put_reqparse().parse_args()
        flask.g.session.login.set_password(args['new_password'])
        return {
            'id': flask.g.login.get_id_unicode(),
        }

    @staticmethod
    def put_reqparse():
        """
        Prepares the request parser for the put method

        :return: The request parser
        :rtype flask_restful.reqparse.RequestParser
        """
        parser = flask_restful.reqparse.RequestParser()
        parser.add_argument(
            name='new_password',
            type=str,
            help='The new password to be set',
            trim=True,
            required=True
        )
        return parser

api.add_resource(Auth, '/auth')
