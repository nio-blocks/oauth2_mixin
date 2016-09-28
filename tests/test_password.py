from unittest.mock import patch, MagicMock
from requests import Response
from ..oauth2_password import OAuth2PasswordGrant
from nio.block.base import Block
from nio.testing.block_test_case import NIOBlockTestCase


class OAuthBlock(OAuth2PasswordGrant, Block):

    def get_oauth_base_url(self):
        return 'http://oauthbase/'


class TestOAuth2PasswordGrant(NIOBlockTestCase):

    @patch('requests.post')
    def test_get_token(self, get_token):
        the_response = Response()
        the_response.status_code = 200
        the_response.json = MagicMock(return_value={'access_token': 'foobar'})
        get_token.return_value = the_response

        block = OAuthBlock()
        self.configure_block(block, {})
        self.assertFalse(block.authenticated())

        token = block.get_access_token('user', 'pass', addl_params={
            'extra': 'value'
        })

        self.assertEqual(token['access_token'], 'foobar')
        self.assertEqual(block.get_access_token_headers(), {
            'Authorization': 'Bearer foobar'
        })

        get_token.assert_called_once_with(
            'http://oauthbase/token',
            data={
                'username': 'user',
                'password': 'pass',
                'grant_type': 'password',
                'extra': 'value'
            })

        self.assertTrue(block.authenticated())

    @patch('requests.post')
    def test_get_token_with_scope(self, get_token):
        the_response = Response()
        the_response.status_code = 200
        the_response.json = MagicMock(return_value={'access_token': 'foobar'})
        get_token.return_value = the_response

        block = OAuthBlock()
        self.configure_block(block, {})
        token = block.get_access_token(
            'user', 'pass',
            scope='my-scope',
            addl_params={
                'extra': 'value'
            })

        self.assertEqual(token['access_token'], 'foobar')
        self.assertEqual(block.get_access_token_headers(), {
            'Authorization': 'Bearer foobar'
        })

        get_token.assert_called_once_with(
            'http://oauthbase/token',
            data={
                'username': 'user',
                'password': 'pass',
                'scope': 'my-scope',
                'grant_type': 'password',
                'extra': 'value'
            })
