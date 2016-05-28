import json
from os.path import join, dirname, realpath, isfile


class OAuth2Exception(Exception):
    pass


class OAuth2Base():

    def __init__(self):
        super().__init__()
        self._oauth_token = None

    def get_oauth_base_url(self):
        """ Returns the base URL for the oauth API.

        You probably want to override this in your block. Include the
        trailing slash for the URL
        """
        return 'https://accounts.google.com/o/oauth2/'

    def get_oauth_url(self, endpoint):
        """ Gets the OAuth URL for a given endpoint.

        This will call get_oauth_base_url and append the passed endpoint
        to the result.

        Example:
        >>> self.get_oauth_url('token')
        'https://accounts.google.com/o/oauth2/token'
        """
        return '{}{}'.format(self.get_oauth_base_url(), endpoint)

    def get_access_token(self, scope=''):
        """ Override in the subclass - This method retrieves an access token.

        Returns:
            None - the access token information is saved to the class instead.
        """
        raise NotImplementedError

    def get_access_token_headers(self,
                                 bearer_text='Bearer',
                                 key='access_token'):
        """ Get the HTTP Request headers for a given access token.

        Args:
            bearer_text (str): The text to use for the authorization type,
                defaults to "Bearer"
            key (str): The key in which the token text can be found in the
                saved token info, defaults to "access_token"

        """
        if self._oauth_token is None:
            raise OAuth2Exception("Token not retrieved")
        return {"Authorization": "{} {}".format(
            bearer_text, self._oauth_token.get(key))}

    def authenticated(self):
        return self._oauth_token is not None

    def parse_token_from_response(self, response):
        if response.status_code != 200:
            raise OAuth2Exception(response.json().get(
                'error', 'Token Request Failed'))
        try:
            token = response.json()
        except:
            self.logger.warning("Token is not JSON parseable")
            token = response.text

        self._oauth_token = token
        return token


    def _load_json_file(self, filename):
        """ Loads the configured JSON filename """

        if filename is None:
            raise OAuth2Exception(
                "Could not find key file {0}. Should be an absolute path or "
                "relative to the current environment.".format(
                    self.key_config_file))

        with open(filename) as json_file:
            return json.load(json_file)

    def _get_valid_file(self, *args):
        """ Go through args and return the first valid file, None if none are.
        """
        for arg in args:
            if isfile(arg):
                return arg
        return None
