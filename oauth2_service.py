import requests
from nio.properties import FileProperty
from .oauth2_base import OAuth2Base, OAuth2Exception

# consider changing this:
# https://github.com/google/oauth2client/blob/f322ef9cdf59d5e4db310baeec2224b914d468c5/CHANGELOG.md
from oauth2client.service_account import ServiceAccountCredentials


class OAuth2ServiceAccount(OAuth2Base):

    # A string representing where to find the private key json file. The file
    # should follow the format of the file generated by clicking Download JSON
    # from the Google Developers Console
    key_config_file = FileProperty(
        title="Private Key Config File", default="etc/private_key.json")

    def get_access_token(self, scope='', token_endpoint='token'):
        """ Obtain an access token for the specified scope

        Args:
            scope (str): The OAuth scope to get a token for

        Returns:
            token (str): The resulting access token

        Raises:
            OAuth2Exception: If the token request fails for any reason
        """
        key_info = self._load_json_file(self.key_config_file())

        if key_info is None:
            raise OAuth2Exception("Invalid Key File: %s" %
                                  self.key_config_file())

        # 'invalid_grant' error unless the correct token_uri is passed.
        # try either of these:
        # https://accounts.google.com/o/oauth2/token
        # https://www.googleapis.com/oauth2/v4/token
        cred = ServiceAccountCredentials.from_json_keyfile_dict(
            key_info,
            token_uri='https://accounts.google.com/o/oauth2/token',
            scopes=scope)

        # Request a new token from the token request URL
        token_url = self.get_oauth_url(token_endpoint)

        try:
            r = requests.post(
                token_url,
                data=cred._generate_refresh_request_body(),
                headers=cred._generate_refresh_request_headers()
            )
        except Exception as e:
            raise OAuth2Exception("Could not complete request to %s: %s %s %s"
                                  % (token_url, cred, key_info, e))

        return self.parse_token_from_response(r)
