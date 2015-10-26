# -*- coding: utf-8 -*-
from functools import wraps

from flask import jsonify, g, request
from flask.ext.restful import fields, marshal, NotAcceptable, InternalServerError
from flask.wrappers import Response
import flask_restful.reqparse

from simple_backend.models import db

__author__ = 'mys'


def parse_request_args(list_of_args, req=None, strict=False):
    """Parses the arguments given.

    :param list_of_args: List of arguments
    :param req: The request context (defaults to flask.request)
    :param strict: Should all parameters be present?

    :type list_of_args list[flask_restful.reqparse.Argument]
    :type req flask.request
    :type strict bool

    :return: The dictionary containing the arguments
    :rtype dict

    :raise InternalServerError: If an entry in list_of_args is malformed
    """
    if "application/json" != request.mimetype:
        raise NotAcceptable(description="Request must have Content-Type: application/json")
    # Prepare the request parser
    parser = flask_restful.reqparse.RequestParser(namespace_class=dict, bundle_errors=True)
    try:
        for arg in list_of_args:
            # All all arguments
            parser.add_argument(**arg)
    except TypeError:
        raise InternalServerError(description="Internal Server Error")
    return parser.parse_args(req=req, strict=strict)


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
            # -- OWASP: Validate response types
            # It is common for REST services to allow multiple response types (e.g. application/xml or application/json,
            # and the client specifies the preferred order of response types by the Accept header in the request.
            # Implementation from http://flask.pocoo.org/snippets/45/
            best = request.accept_mimetypes.best_match(['application/json', 'text/html'])
            if best != 'application/json' or request.accept_mimetypes[best] < request.accept_mimetypes['text/html']:
                raise NotAcceptable(description="Client must prefer 'application/json' as Accept")

            result = fn(*args, **kwargs)
            if 'status' not in result or result['status'] < 100:
                result['status'] = 200
            if 'message' not in result or result['message'] is None:
                if result['status'] == 200:
                    result['message'] = 'OK'
                else:
                    result['message'] = 'Error'
            if hasattr(g, 'session'):
                # Override token if session is present
                result['token'] = g.session.token
                token_time = min(g.login.roles, key=lambda x: x.token_time).token_time
            else:
                result['token'] = None
                token_time = None

            result = marshal(result, self.marshalling)
            response = jsonify(result)
            assert isinstance(response, Response)
            # Set the RESTful headers
            response.status_code = result['status']
            response.content_type = 'application/json; charset=utf-8'
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = 0
            # -- OWASP: Send security headers
            # The server should also send an X-Content-Type-Options: nosniff to make sure the browser does not try
            # to detect a different Content-Type than what is actually sent (can lead to XSS).
            response.headers['X-Content-Type-Options'] = 'nosniff'
            # -- OWASP: Send security headers
            # Additionally the client should send an X-Frame-Options: deny to protect against drag'n drop clickjacking
            # attacks in older browsers.
            response.headers['X-Frame-Options'] = 'deny'
            # If we have a token, set the cookie as well
            if result['token'] is not None:
                response.set_cookie('token', result['token'], max_age=token_time)

            # The very last thing to do is to update everything
            db.session.commit()
            return response

        return decorated_view
