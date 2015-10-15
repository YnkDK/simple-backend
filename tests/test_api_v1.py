#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import unittest
import json

from api import create_app
from api.auth.models import user_collection


class APIV1TestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(environment="Testing")

    def test_hello_version(self):
        client = self.app.test_client()
        request = client.get('/api/auth')

        self.assertEqual(request.status_code, 401)
        data = json.loads(request.data)
        self.assertEqual(data['message'], 'Unauthorized')

        with self.app.app_context():
            # Create test roles
            admin_role = user_collection.create_role(name='admin', description='The administrator', token_renew=True)
            spammer_role = user_collection.create_role(name='spammer', description='The spammer')
            # Create test users
            ynk_user = user_collection.create_user(email='ms@ynk.gl', password='SecretPassword',
                                                   roles=[admin_role, spammer_role])
            spam_user = user_collection.create_user(email='spam', password='SecretPassword', roles=[spammer_role])

            # Check that login with correct credentials works
            request = client.post('/api/auth',
                                  headers={'Authorization': 'Basic ' + base64.b64encode('ms@ynk.gl:SecretPassword')})
            self.assertEqual(request.status_code, 200)
            data = json.loads(request.data)
            self.assertIn('token', data)
            token = base64.b64encode(data['token'] + ':unused')
            # Check that a protected resource can be accessed
            request = client.get('/api/auth', headers={'Authorization': 'Basic ' + token})
            self.assertEqual(request.status_code, 200)
            data = json.loads(request.data)
            self.assertEqual(data['id'], ynk_user.get_id_unicode())
            self.assertNotEqual(base64.b64encode(data['token'] + ':unused'), token)


            # Request with the old token should be rejected
            request = client.get('/api/auth', headers={'Authorization': 'Basic ' + token})
            self.assertEqual(request.status_code, 401)
            # Request wuth the new token should be accepted
            request = client.get('/api/auth',
                                 headers={'Authorization': 'Basic ' + base64.b64encode(data['token'] + ':unused')})
            self.assertEqual(request.status_code, 200)
            # Check for spam
            request = client.post('/api/auth',
                                  headers={'Authorization': 'Basic ' + base64.b64encode('spam:SecretPassword')})
            self.assertEqual(request.status_code, 200)
            request = client.post('/api/auth',
                                  headers={'Authorization': 'Basic ' + base64.b64encode('spam:SecretPassword')})
            self.assertEqual(request.status_code, 200)
            data = json.loads(request.data)
            self.assertIn('token', data)
            token = base64.b64encode(data['token'] + ':unused')
            # Check that a protected resource cannot be accesses with a spam user
            request = client.get('/api/auth', headers={'Authorization': 'Basic ' + token})
            self.assertEqual(request.status_code, 401)
            data = json.loads(request.data)
            self.assertEqual(data['message'], 'Unauthorized')


if __name__ == '__main__':
    unittest.main()
