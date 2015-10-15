#!/usr/bin/python
# -*- coding: utf-8 -*-
import base64
import unittest
import json

from api import create_app
from api.auth.models import user_collection


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(environment="Testing")
        self.client = self.app.test_client()
        self.client.get('blabla')

    def tearDown(self):
        self.app = None
        self.client = None

    def _create_users(self):
        # Set up two roles
        admin_role = user_collection.create_role(name='admin', description='The administrator', token_renew=True)
        non_admin_role = user_collection.create_role(name='non-admin', description='The non-admin role',
                                                     token_renew=False)
        # Set up some users
        user_collection.create_user(email='admin', password='Str0ngPwd!',
                                    roles=[admin_role])
        user_collection.create_user(email='scanty', password='123',
                                    roles=[non_admin_role])
        user_collection.create_user(email='multi', password='!"#',
                                    roles=[admin_role, non_admin_role])

    def _login(self, email, password):
        return self.client.post('/api/auth', headers={
            'Authorization': 'Basic ' + base64.b64encode(email + ':' + password)
        })

    def _get_resource(self, email, password):
        return self.client.get('/api/auth', headers={
            'Authorization': 'Basic ' + base64.b64encode(email + ':' + password)
        })

    def test_happy_login(self):
        with self.app.app_context():
            # Create all users in the current context
            self._create_users()
            # Login the admin
            response = self._login('admin', 'Str0ngPwd!')
            # Check that the status code is present
            self.assertEqual(200, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message', 'token'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'OK'
            self.assertEqual(data['message'], 'OK')
            # Check that the token is not None
            self.assertNotEqual(data['token'], None)
            # Check that the token is unicode
            self.assertTrue(type(data['token']) == unicode)
            # Check that the token is the non-empty string
            self.assertGreater(len(data['token']), 0)

            # Login the scanty
            response = self._login('scanty', '123')
            # Check that the status code is present
            self.assertEqual(200, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message', 'token'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'OK'
            self.assertEqual(data['message'], 'OK')
            # Check that the token is not None
            self.assertNotEqual(data['token'], None)
            # Check that the token is unicode
            self.assertTrue(type(data['token']) == unicode)
            # Check that the token is the non-empty string
            self.assertGreater(len(data['token']), 0)

            # Login the admin
            response = self._login('multi', '!"#')
            # Check that the status code is present
            self.assertEqual(200, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message', 'token'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'OK'
            self.assertEqual(data['message'], 'OK')
            # Check that the token is not None
            self.assertNotEqual(data['token'], None)
            # Check that the token is unicode
            self.assertTrue(type(data['token']) == unicode)
            # Check that the token is the non-empty string
            self.assertGreater(len(data['token']), 0)

    def test_wrong_credentials(self):
        with self.app.app_context():
            # Create all users in the current context
            self._create_users()
            # Login with wrong credentials
            response = self._login('admin', '123')
            # Check that the status code corresponds to unauthorized
            self.assertEqual(401, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'Unauthorized'
            self.assertEqual(data['message'], 'Unauthorized')

            # Login with wrong credentials
            response = self._login('Str0ngPwd!', 'admin')
            # Check that the status code corresponds to unauthorized
            self.assertEqual(401, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'Unauthorized'
            self.assertEqual(data['message'], 'Unauthorized')

            # Login with wrong credentials
            response = self._login('\x00', '')
            # Check that the status code corresponds to unauthorized
            self.assertEqual(401, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'Unauthorized'
            self.assertEqual(data['message'], 'Unauthorized')

    def test_token_access(self):
        with self.app.app_context():
            self._create_users()
            response = self._login('admin', 'Str0ngPwd!')
            data = json.loads(response.data)
            token1 = data['token']
            response = self._get_resource(token1, '')
            # Check that the status code is present
            self.assertEqual(200, response.status_code)
            # Parse the response
            data = json.loads(response.data)
            # Check that all keys are present
            self.assertEquals({'status', 'message', 'token', 'id'}, set(data.keys()))
            # Check that the status is correct
            self.assertEqual(data['status'], response.status_code)
            # Check that the message is 'OK'
            self.assertEqual(data['message'], 'OK')
            # Check that the token is not None
            self.assertNotEqual(data['token'], None)
            # Check that the token is unicode
            self.assertTrue(type(data['token']) == unicode)
            # Check that the token is the non-empty string
            self.assertGreater(len(data['token']), 0)

            # Check that the admin role got a new token
            self.assertNotEqual(token1, data['token'])

            # Check that the old token is invalid
            response = self._get_resource(token1, '')
            self.assertEqual(401, response.status_code)

            # Check the the new token is valid
            response = self._get_resource(data['token'], '')
            self.assertEqual(200, response.status_code)

    def test_role_access(self):
        with self.app.app_context():
            self._create_users()
            """ Scanty login - no access excepted """
            # First try to access with credentials
            response = self._get_resource('scanty', '123')
            self.assertEqual(401, response.status_code)
            # Then try to access with generated token
            response = self._login('scanty', '123')
            data = json.loads(response.data)
            response = self._get_resource(data['token'], '')
            self.assertEqual(401, response.status_code)
            """ Multi login - access excepted """
            response = self._get_resource('multi', '!"#')
            # First try to access with credentials
            self.assertEqual(200, response.status_code)
            # Then try to access with generated token
            response = self._login('multi', '!"#')
            data = json.loads(response.data)
            response = self._get_resource(data['token'], '')
            self.assertEqual(200, response.status_code)
            """ Admin login - access excepted """
            response = self._get_resource('admin', 'Str0ngPwd!')
            # First try to access with credentials
            self.assertEqual(200, response.status_code)
            # Then try to access with generated token
            response = self._login('admin', 'Str0ngPwd!')
            data = json.loads(response.data)
            response = self._get_resource(data['token'], '')
            self.assertEqual(200, response.status_code)

    def test_token_renew(self):
        with self.app.app_context():
            self._create_users()
            """ Multi login - renewal excepted """
            response = self._login('multi', '!"#')
            data = json.loads(response.data)
            token1 = data['token']
            response = self._get_resource(token1, '')
            data = json.loads(response.data)
            token2 = data['token']
            response = self._get_resource(token1, '')
            self.assertEqual(401, response.status_code)
            response = self._get_resource(token2, '')
            self.assertEqual(200, response.status_code)

            """ Admin login - renewal excepted """
            response = self._login('admin', 'Str0ngPwd!')
            data = json.loads(response.data)
            token1 = data['token']
            response = self._get_resource(token1, '')
            data = json.loads(response.data)
            token2 = data['token']
            response = self._get_resource(token1, '')
            self.assertEqual(401, response.status_code)
            response = self._get_resource(token2, '')
            self.assertEqual(200, response.status_code)

    def test_invalid_session(self):
        with self.app.app_context():
            self._create_users()
            response = self._login('admin', 'Str0ngPwd!')
            token1 = json.loads(response.data)['token']
            response = self._login('admin', 'Str0ngPwd!')
            token2 = json.loads(response.data)['token']
            # At this point token1 should be invalid and token2 valid
            self.assertNotEqual(token1, token2)
            # See that the first is invalid
            response = self._get_resource(token1, '')
            self.assertEqual(401, response.status_code)
            # See that the second is valid
            response = self._get_resource(token2, '')
            self.assertEqual(200, response.status_code)



if __name__ == '__main__':
    unittest.main()
