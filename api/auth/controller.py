#!/usr/bin/python
# -*- coding: utf-8 -*-

import flask
import flask_restful
import flask_restful.reqparse
from flask import g

from api.auth.constants import MARSHAL_GET, MARSHAL_POST
from api.models import db, Session
from api.auth.models import http_basic_auth
from util import roles_accepted, marshal_output

__author__ = 'mys'

bp = flask.Blueprint('api_v1', __name__)
api = flask_restful.Api(bp)


class Auth(flask_restful.Resource):
    @http_basic_auth.login_required  # First ensure that the user is logged in
    @roles_accepted('admin')  # Then check that the user have a correct role
    @flask_restful.marshal_with(MARSHAL_GET)  # Then enforce the marshalling
    @marshal_output  # Lastly,set the basic marshals, i.e. message, status and token
    def get(self):
        return {
            'id': g.login.get_id_unicode(),
        }

    @http_basic_auth.login_required
    @flask_restful.marshal_with(MARSHAL_POST)
    def post(self):
        # Get the token
        token = g.login.generate_auth_token()

        # Update the session
        session = Session.query.filter_by(login_id=g.login.id).first()
        if not session:
            session = Session(token=token, login_id=g.login.id)
            db.session.add(session)
        else:
            session.clear(token)
        db.session.commit()

        return {
            'status': 200,
            'message': 'OK',
            'token': token.decode('ascii')
        }

    @http_basic_auth.login_required
    @flask_restful.marshal_with(MARSHAL_GET)
    @marshal_output
    def put(self):
        # TODO: Admin should be able to change other users
        # TODO: Admin should be able to change roles for other users
        args = self.put_reqparse().parse_args()
        g.session.login.set_password(args['new_password'])
        return {
            'id': g.login.get_id_unicode(),
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
