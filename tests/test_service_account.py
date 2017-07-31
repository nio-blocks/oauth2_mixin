from unittest.mock import patch, MagicMock
from requests import Response
from ..oauth2_base import OAuth2Exception
from ..oauth2_service import OAuth2ServiceAccount
from nio.block.base import Block
from nio.testing.block_test_case import NIOBlockTestCase
from nio.util.discovery import not_discoverable


@not_discoverable
class OAuthBlock(OAuth2ServiceAccount, Block):
    pass


class TestOAuth2ServiceAccount(NIOBlockTestCase):

    @patch.object(OAuth2ServiceAccount, '_load_json_file',
                  return_value={'client_email': 'foo@bar.gov',
                                'private_key': 'WhatAKey',
                                'type': 'service_account',
                                'private_key_id': 'WhatAnID',
                                'client_id': 'WhatAClientID'})
    @patch('requests.post')
    @patch.object(OAuth2ServiceAccount, 'get_access_token',
                  return_value={'access_token': 'foobar'})
    def test_token(self, mock_head, mock_post, mock_service_creds):

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

        self.assertEqual(token['access_token'], 'foobar')
        
        # Oauth2ServiceAccount.get_access_token is mocked, but the method
        # assigns self._oauth_token inside of the method.
        # Need to assign it here before checking block.get_access_token_headers
        block._oauth_token = {'access_token': 'foobar'}
        self.assertEqual(block.get_access_token_headers(), {
            'Authorization': 'Bearer foobar'
        })

    def test_bad_scope(self):
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/KEY_FILE_GOES_HERE.json"
        })

        with self.assertRaises(OAuth2Exception):
            block.get_access_token('not-a-scope')

    def test_bad_key_file(self):
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/KEY_FILE_GOES_HERE.json"
        })

        with patch.object(block, '_load_json_file') as load_file:
            load_file.return_value = None
            with self.assertRaises(OAuth2Exception):
                block.get_access_token()
