from unittest.mock import patch, MagicMock
from requests import Response
from ..oauth2 import OAuth2, OAuth2Exception
from nio.common.block.base import Block
from nio.util.support.block_test_case import NIOBlockTestCase


class OAuthBlock(OAuth2, Block):
    pass


class TestOAuth2Mixin(NIOBlockTestCase):

    @patch.object(OAuth2, '_load_json_file',
                  return_value={'client_email': 'foo@bar.gov',
                                'private_key': 'WhatAKey'})
    @patch('requests.post')
    @patch('oauth2client.client.SignedJwtAssertionCredentials.'
           '_generate_refresh_request_body')
    @patch('oauth2client.client.SignedJwtAssertionCredentials.'
           '_generate_refresh_request_headers')
    def test_token(self, mock_head, mock_bod, mock_post, mock_load):
        
        # mock out the token request response
        the_response = Response()
        the_response.status_code = 200
        the_response.json = MagicMock(return_value={'access_token': 'foobar'})
        mock_post.return_value = the_response
        
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/KEY_FILE_GOES_HERE.json"
        })

        token = block.get_access_token(
            'https://www.googleapis.com/auth/analytics.readonly')

        self.assertEqual(token, 'foobar')

    def test_bad_scope(self):
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/KEY_FILE_GOES_HERE.json"
        })

        with self.assertRaises(OAuth2Exception):
            block.get_access_token('not-a-scope')
