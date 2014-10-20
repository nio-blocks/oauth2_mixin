from ..oauth2 import OAuth2, OAuth2Exception
from nio.common.block.base import Block
from nio.util.support.block_test_case import NIOBlockTestCase


class OAuthBlock(OAuth2, Block):
    pass


class TestOAuth2Mixin(NIOBlockTestCase):

    def test_token(self):
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/KEY_FILE_GOES_HERE.json"
        })

        token = block.get_access_token(
            'https://www.googleapis.com/auth/analytics.readonly')

        self.assertIsNotNone(token)

    def test_bad_scope(self):
        block = OAuthBlock()
        self.configure_block(block, {
            "key_config_file": "tests/GoBuffs-e254fba1cd4a.json"
        })

        with self.assertRaises(OAuth2Exception):
            block.get_access_token('not-a-scope')
