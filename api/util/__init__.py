# -*- coding: utf-8 -*-
from functools import wraps

from flask import jsonify, g
from flask.ext.restful import fields, marshal

from api.models import db

__author__ = 'mys'


def roles_accepted(*roles):
    """A modification of the decorator defined in flask.ext.login.roles_accepted.
    The decorator specifies that a user must have at least one of the
    specified roles. Example::

        @roles_accepted('editor', 'author')
        def create_post():
            return 'Create Post'

    The current user must have either the `editor` role or `author` role in
    order to view the page.

    :param args: The possible roles.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            user_roles = set([role.name for role in g.login.roles])
            accepted_roles = set(roles)

            if len(user_roles.intersection(accepted_roles)) > 0:
                # Role can access this resource
                return fn(*args, **kwargs)
            # Could not access this resource, prepare response
            response = jsonify({
                'message': 'Unauthorized',
                'status': 401
            })
            # response.headers = {'WWW-Authenticate': 'Basic realm="Login Required"'}
            response.status_code = 401
            return response

        return decorated_view

    return wrapper


def tokenify_marshal(d):
    """
    Sets the response tokenify_output to use the standard tokenify_output response in addition with the given parameter
    :param d: The specific parameter
    :type d dict

    :return The updated marshalling keys
    :rtype dict
    """
    d.update({
        'message': fields.String,
        'status': fields.Integer,
        'token': fields.String
    })
    return d


class tokenify_output(object):
    def __init__(self, marshalling):
        self.marshalling = marshalling

    def __call__(self, fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            result = fn(*args, **kwargs)
            if not 'status' in result or result['status'] < 100:
                result['status'] = 200
            if not 'message' in result or result['message'] is None:
                if result['status'] == 200:
                    result['message'] = 'OK'
                else:
                    result['message'] = 'Error'
            if hasattr(g, 'session'):
                # Override token if session is present
                result['token'] = g.session.token

            result = marshal(result, self.marshalling)
            response = jsonify(result)
            response.status_code = result['status']
            token_time = min(g.login.roles, key=lambda x: x.token_time).token_time
            response.set_cookie('token', '', max_age=token_time)

            # The very last thing to do is to update everything
            db.session.commit()
            return response

        return decorated_view
