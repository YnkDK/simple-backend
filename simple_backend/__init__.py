#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import inspect

from flask import Flask
from flask.ext.restful import fields
from flask.ext.security import Security
from flask.ext.login import LoginManager
from werkzeug.exceptions import NotFound, MethodNotAllowed, InternalServerError

from simple_backend.models import db
from util import tokenify_output, tokenify_marshal
from util.reqparse import RequestParserException


def no_more_blueprints(*args, **kwargs):
    raise RuntimeError('All blueprints must be added in create_app constructor')


def create_error_handlers(app):
    @app.errorhandler(RequestParserException)
    @tokenify_output(tokenify_marshal({'usage': fields.String}))
    def request_parser_exception(exception):
        """
        :type exception RequestParserException
        """
        return {
            'message': exception.message,
            'status': exception.code,
            'usage': exception.usage
        }

    @app.errorhandler(NotFound)
    @app.errorhandler(404)
    @tokenify_output(tokenify_marshal({}))
    def resource_not_found(exception):
        """
        :type exception NotFound
        """
        return {
            'message': exception.description,
            'status': exception.code
        }

    @app.errorhandler(MethodNotAllowed)
    @app.errorhandler(405)
    @tokenify_output(tokenify_marshal({}))
    def method_not_allowed(exception):
        """
        :type exception MethodNotAllowed
        """
        return {
            'message': exception.description,
            'status': exception.code
        }

    @app.errorhandler(InternalServerError)
    @app.errorhandler(500)
    @tokenify_output(tokenify_marshal({}))
    def internal_server_error(exception):
        """
        :type exception InternalServerError
        """
        return {
            'message': exception.description,
            'status': exception.code
        }


def create_app(
        environment=None,
        security_class=Security,
        login_manager_class=LoginManager,
        register_auth_blueprint=True,
        error_handlers=create_error_handlers,
        blueprints=None):
    app = Flask(__name__)
    # flask_restful.Api does something strange with the exception handling, save them for later
    handle_user_exception = app.handle_user_exception
    handle_exception = app.handle_exception
    # Read the config
    if environment is None:
        environment = os.environ.get('FLASK_CONFIG', 'development')
    app.config.from_object('simple_backend.config.{}'.format(environment.capitalize()))
    if __debug__:
        print 'Using configuration for', environment.capitalize()

    if inspect.isclass(security_class):
        from simple_backend.auth.models import user_collection
        security = security_class()
        security.init_app(app, user_collection)

    if inspect.isclass(login_manager_class):
        from simple_backend.auth.models import Anonymous
        login_manager = login_manager_class()
        # Setup login_manager
        login_manager.anonymous_user = Anonymous
        # Init app with the extensions
        login_manager.init_app(app)
    db.init_app(app)
    if register_auth_blueprint:
        import simple_backend.auth
        app.register_blueprint(
            auth.blueprint,
            url_prefix='{prefix}'.format(
                prefix=app.config['URL_PREFIX']
            )
        )
    if blueprints is not None:
        from flask import Blueprint
        for blueprint in blueprints:
            assert isinstance(type(blueprint), Blueprint)
            app.register_blueprint(
                blueprint,
                url_prefix='{prefix}'.format(
                    prefix=app.config['URL_PREFIX']
                )
            )
    elif __debug__:
        print 'Warning: It is not possible to add any blueprints after this message!'

    app.register_blueprint = no_more_blueprints
    # flask_restful.Api does something strange with the exception handling, set them back to defaults before
    # registering the custom error handlers
    app.handle_exception = handle_exception
    app.handle_user_exception = handle_user_exception

    if inspect.isfunction(error_handlers):
        error_handlers(app)

    return app
