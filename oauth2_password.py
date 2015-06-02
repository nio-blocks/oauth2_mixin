import requests
from .oauth2_base import OAuth2Base, OAuth2Exception


class OAuth2PasswordGrant(OAuth2Base):

    def get_access_token(
            self, username='', password='', scope='', addl_params=None,
            token_endpoint='token', grant_type='password'):
        """ Obtain an access token for the specified credentials

        Args:
            username (str): The username credential
            password (str): The password credential
            scope (str): The (optional) OAuth scope to get a token for
            addl_params (dict): A dictionary of additional form data to
                include in the token request
            token_endpoint (str): The endpoint where the token request
                should be made - relative to the base URL
            grant_type (str): The grant type for the request

        Returns:
            The token information in a dictionary. It also saves this value
            to the class instance for use in other functions.

        Raises:
            OAuth2Exception: If the token request fails for any reason
        """
        token_url = self.get_oauth_url(token_endpoint)

        form_data = {
            'username': username,
            'password': password,
            'grant_type': grant_type
        }
        if scope:
            form_data['scope'] = scope
        if addl_params:
            form_data.update(addl_params)

        # Request a new token from the token request URL
        try:
            r = requests.post(token_url, data=form_data)
        except:
            raise OAuth2Exception("Could not complete request to {0}".format(
                token_url))

        return self.parse_token_from_response(r)
