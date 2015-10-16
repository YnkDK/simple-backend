# -*- coding: utf-8 -*-
from api.util import tokenify_marshal

__author__ = 'mys'
from flask.ext.restful import fields

PEPPERS = [chr(i) for i in xrange(256)]
# Define the marshalling transformation for the GET method
MARSHAL_GET = tokenify_marshal({
    'id': fields.String
})

# Define which roles can access GET
ROLES_GET = ('admin')

MARSHAL_POST = tokenify_marshal({})
