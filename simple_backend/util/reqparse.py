# -*- coding: utf-8 -*-
import flask_restful
import flask_restful.reqparse
from flask import request
from werkzeug import exceptions

__author__ = 'mys'


class RequestParserException(Exception):
    code = 400
    payload = None

    def __init__(self, original_exception, usage):
        assert hasattr(original_exception, 'message')
        self.original_exception = original_exception
        self.usage = usage
        super(RequestParserException, self).__init__(original_exception.message, 400)

    @property
    def message(self):
        return self.original_exception.message


class RequestParser(flask_restful.reqparse.RequestParser):
    def __init__(self, argument_class=flask_restful.reqparse.Argument, namespace_class=dict,
                 trim=False, bundle_errors=True):
        """
        Changed defaults for:
            - namespace_class, uses a standard dict
            - bundle_errors, now bundles errors instead of aborting
        """
        super(RequestParser, self).__init__(argument_class, namespace_class, trim, bundle_errors)

    def parse_args(self, req=None, strict=False):
        """Parse all arguments from the provided request and return the results
        as a Namespace

        Changed: Instead of aborting, an RequestParserException is raised

        :param strict: if req includes args not in parser, throw 400 BadRequest exception

        :raise RequestParserException: on the first request parsing error
        """
        if req is None:
            req = request

        namespace = self.namespace_class()

        # A record of arguments not yet parsed; as each is found
        # among self.args, it will be popped out
        req.unparsed_arguments = dict(self.argument_class('').source(req)) if strict else {}
        for arg in self.args:
            value, found = arg.parse(req, self.bundle_errors)
            if isinstance(value, ValueError):
                value.message = "The argument '{:s}' {:s}".format(
                    arg.dest or arg.name,
                    value.message
                )
                raise RequestParserException(value, arg.help)
            if found or arg.store_missing:
                namespace[arg.dest or arg.name] = value

        if strict and req.unparsed_arguments:
            raise RequestParserException(
                exceptions.BadRequest(u'Unknown arguments: {0:s}'
                                      .format(', '.join(req.unparsed_arguments.keys()))
                                      ),
                'Remove unknown arguments'
            )
        return namespace
