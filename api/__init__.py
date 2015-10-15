#!/usr/bin/python
# -*- coding: utf-8 -*-

import os

from flask import Flask
from flask.ext.security import Security
from flask.ext.login import LoginManager

from api.models import db
import api.auth


def create_app(environment=None):
    app = Flask(__name__)
    security = Security()
    login_manager = LoginManager()
    if not environment:
        environment = os.environ.get('FLASK_CONFIG', 'development')
    app.config.from_object('api.config.{}'.format(environment.capitalize()))
    app.config.from_pyfile(
        'config_{}.py'.format(environment.lower()),
        silent=True
    )

    # Import all models
    from api.auth.models import Anonymous, user_collection
    # Setup login_manager
    login_manager.anonymous_user = Anonymous

    # Init app with the extensions


    security.init_app(app, user_collection)
    login_manager.init_app(app)
    db.init_app(app)


    # Lastly: Register the blueprints
    app.register_blueprint(
        auth.blueprint,
        url_prefix='{prefix}'.format(
            prefix=app.config['URL_PREFIX']
        )
    )

    @app.before_first_request
    def init_in_context():
        db.create_all()
        # admin_role = user_collection.create_role(name='admin', description='The administrator')
        # ynk_user = user_collection.create_user(email='admin', password='SecretPassword', roles=[admin_role])
        db.session.commit()
        # print User.query.all()

    return app
