# -*- coding: utf-8 -*-
from api.util import response_marshal

__author__ = 'mys'
from flask.ext.restful import fields

PEPPERS = [chr(i) for i in xrange(256)]
# Define the marshalling transformation for the GET method
MARSHAL_GET = response_marshal({
    'id': fields.String
})

# Define which roles can access GET
ROLES_GET = ('admin')

MARSHAL_POST = response_marshal({})
