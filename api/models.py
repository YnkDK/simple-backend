#!/usr/bin/python
# -*- coding: utf-8 -*-
from datetime import datetime
import uuid

from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy_utils import UUIDType

__author__ = 'mys'

db = SQLAlchemy()


class Session(db.Model):
    id = db.Column(UUIDType, primary_key=True)
    token = db.Column(db.String)
    login_id = db.Column(UUIDType, db.ForeignKey('login.id'), unique=True)
    last_verified = db.Column(db.TIMESTAMP, default=datetime.utcnow())

    def __init__(self, **kwargs):
        super(Session, self).__init__(**kwargs)
        self.id = uuid.uuid4()

    def clear(self, token=None):
        self.token = token
        self.last_verified = datetime.utcnow()
