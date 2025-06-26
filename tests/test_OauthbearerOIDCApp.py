import urllib.parse
from trivup.apps.OauthbearerOIDCApp import WebServerHandler
import urllib


class WebServerHandlerSpy(WebServerHandler):
    def __init__(self, public_key=None):
        super().__init__(public_key)
        self.error_code = None
        self.message = None

    def send_error(self, code, message, *args):
        self.error_code = code
        self.message = message


def test_none_post_data_validation():
    handler = WebServerHandlerSpy()
    assert not handler.valid_post_data(None)
    assert handler.error_code == 400
    assert 'grant_type=client_credentials and scope' in handler.message


def test_invalid_grant_type_validation():
    handler = WebServerHandlerSpy()
    post_data = urllib.parse.urlencode(
        {'grant_type': 'invalid_grant_type',
         'scope': 'test'})
    assert not handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code == 400
    assert 'format of data should be grant_type=' in handler.message


def test_client_credentials_validation():
    handler = WebServerHandlerSpy()
    post_data = urllib.parse.urlencode(
        {'grant_type': 'client_credentials',
         'scope': 'test'})
    assert handler.valid_post_data(post_data.encode('utf-8'), True)
    assert handler.error_code is None
    assert handler.message is None

    assert not handler.valid_post_data(post_data.encode('utf-8'), False)
    assert handler.error_code == 400
    assert 'Authorization field is required' in handler.message

    post_data = urllib.parse.urlencode(
        {'grant_type': 'client_credentials',
         'scope': 'invalid_scope'})
    assert not handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code == 400
    assert 'Invalid scope' in handler.message


def test_jwt_bearer_validation():
    def make_post_data(assertion):
        return urllib.parse.urlencode(
            {'grant_type': WebServerHandler.JWT_BEARER_GRANT_TYPE,
             'assertion': assertion})

    public_key, key = WebServerHandler.generate_public_key()

    # No public key provided
    handler = WebServerHandlerSpy()
    token = WebServerHandler.generate_token(key, 4, True)['access_token']
    post_data = make_post_data(token)
    assert not handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code == 500
    assert 'public key is missing' in handler.message

    # Invalid token
    handler = WebServerHandlerSpy(str(public_key).encode())
    token = WebServerHandler.generate_token(key, 4, False)['access_token']
    post_data = make_post_data(token)
    assert not handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code == 400
    assert 'Invalid assertion' in handler.message

    # Invalid token expiration
    handler = WebServerHandlerSpy(str(public_key).encode())
    token = WebServerHandler.generate_token(key, -64, True)['access_token']
    post_data = make_post_data(token)
    assert not handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code == 400
    assert 'Invalid assertion' in handler.message

    # Valid token
    handler = WebServerHandlerSpy(str(public_key).encode())
    token = WebServerHandler.generate_token(key, 4, True)['access_token']
    post_data = make_post_data(token)
    assert handler.valid_post_data(post_data.encode('utf-8'))
    assert handler.error_code is None
    assert handler.message is None
