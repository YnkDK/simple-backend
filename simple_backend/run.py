#!/usr/bin/python
# -*- coding: utf-8 -*-
from simple_backend import create_app
from simple_backend.models import db
from simple_backend.auth.models import user_collection

app = create_app()


@app.before_first_request
def init_in_context():
    db.create_all()
    if user_collection.find_role('admin') is None:
        ###############################
        ## Bootstrap the application ##
        ##        CHANGE ASAP        ##
        ###############################
        admin_role = user_collection.find_or_create_role(name='admin', description='The administrator',
                                                         token_renew=True)
        # Request a put on 'api/auth' with new_password as data, see test for example
        user_collection.create_user(login='admin', password='Str0ngPwd!',
                                    roles=[admin_role])


if __name__ == "__main__":
    app.run(host=app.config['HOST'], port=app.config['PORT'])
