# -*- coding: utf-8 -*-
__author__ = 'mys'

from flask.ext.restful import fields

from api.util import tokenify_marshal


# Define the marshalling transformation for the GET method
MARSHAL_GET = tokenify_marshal({
    'id': fields.String
})

# Define which roles can access GET
ROLES_GET = ('admin')

MARSHAL_POST = tokenify_marshal({})
