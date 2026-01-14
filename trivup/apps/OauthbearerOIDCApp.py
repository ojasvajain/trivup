#!/usr/bin/env python
#

# Copyright (c) 2021, Magnus Edenhill
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from trivup import trivup
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
from jwcrypto import jwk, jwt
from threading import Lock

import json
import argparse
import requests
import os
import base64
import tempfile
import urllib

VALID_SCOPES = ['test', 'test-scope', 'api://1234-abcd/.default']


class WebServerHandler(BaseHTTPRequestHandler):

    JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer'

    def __init__(self, client_public_key=None):
        self._key = None
        self._public_keys = []
        self._mutex = Lock()
        self.public_key = None
        if client_public_key:
            self.public_key = self.parse_jwk(client_public_key)

    def __call__(self, *args, **kwargs):
        """
        As it turns out, http.server.BaseHTTPRequestHandler
        ultimately inherits from socketserver.BaseRequestHandler,
        and socketserver.BaseRequestHandler.__init__() calls do_GET()
        and do_POST(). So if we add the super().__init__(*args, **kwargs)
        to the constructor of WebServerHandler, it means all the
        instance variables are initialized for each request.
        But the relevant parts of the JWT are cached in the broker.
        The only time the broker communicates with the OAuth/OIDC
        token provider is at a) startup, b) during a scheduled refresh,
        and c) when it finds a key ID that isn't cached.
        So we want to keep the same public key for each user in case
        the broker won't get the new public key immediately.
        So this method keeps the superclass "constructor"
        call out of "constructor" of this class which eliminates the
        possibility of dispatching a request (from the superclass's
        constructor) before the subclass's constructor is finished
        to avoid initializing the instance variables.
        Refer to https://stackoverflow.com/a/58909293
        """
        super().__init__(*args, **kwargs)

    def update_keys(self):
        self._mutex.acquire()
        if len(self._public_keys) == 0:
            public_key, key = WebServerHandler.generate_public_key()
            self._public_keys.append(json.loads(public_key))
            self._key = key
        self._mutex.release()

    def validate_metadata_authentication_azure_imds(self, parsed_get_data):
        if 'client_id' not in parsed_get_data:
            self.send_error(400,
                            'client_id field is required in query parameters')
            return False

        if 'resource' not in parsed_get_data:
            self.send_error(400,
                            'resource field is required in query parameters')
            return False

        if 'api-version' not in parsed_get_data:
            self.send_error(400,
                            'api-version field is required in query parameters'
                            )
            return False

        metadata_header = self.headers.get('Metadata', None)
        if metadata_header is None or metadata_header.lower() != 'true':
            self.send_error(400, 'Metadata header must be set to "true"')
            return False

        return True

    def validate_metadata_authentication(self):
        if self.headers.get('Accept', None) != "application/json":
            self.send_error(400, 'Accept field should be "application/json"')
            return False

        _, after_params = self.path.split('?', 1)
        parsed_get_data = urllib.parse.parse_qs(after_params)
        if '__metadata_authentication_type' not in parsed_get_data:
            self.send_error(400,
                            '__metadata_authentication_type field is '
                            'required in query parameters')
            return False

        metadata_authentication_type = \
            parsed_get_data['__metadata_authentication_type'][0]
        if metadata_authentication_type != 'azure_imds':
            self.send_error(400,
                            '__metadata_authentication_type is not '
                            'a supported type')
            return False

        return self.validate_metadata_authentication_azure_imds(
            parsed_get_data)

    def do_GET(self):
        if self.path.endswith("/keys"):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.update_keys()
            keys = {"keys": self._public_keys}
            self.wfile.write(json.dumps(keys, indent=4).encode())
            return
        elif self.path.startswith("/retrieve?"):
            if not self.validate_metadata_authentication():
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            token = self.generate_key_and_token(60)
            self.wfile.write(json.dumps(token, indent=4).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        message = "HTTP server for OAuth\n"
        message += "Example for token retrieval:\n"
        message += 'curl \
        -X POST \
        --url localhost:PORT/retrieve \
        -H "Accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK \
            (base64 string generated from CLIENT_ID:CLIENT_SECRET)" \
        -d "grant_type=client_credentials,scope=test-scope"'
        self.wfile.write(message.encode())

    @staticmethod
    def generate_token(key, lifetime, valid=True):
        now = int(time.time())
        payload = {
            'exp': now + lifetime,
            'iat': now,
            'iss': "issuer",
            'sub': "subject",
            'aud': 'api://default'
        }
        header = {
            "kid": "abcdefg",
            "alg": "RS256"
        }
        jwt_token = jwt.JWT(header=header, claims=payload,
                            algs=['RS256'])
        jwt_token.make_signed_token(key)
        token = jwt_token.serialize(compact=True)
        if not valid:
            token += "invalid"

        token_map = {"access_token": "%s" % token}
        return token_map

    @staticmethod
    def generate_public_key():

        key = jwk.JWK.generate(kty='RSA', size=2048, alg='RS256',
                               use='sig', kid="abcdefg")

        public_key = key.export_public()
        return (public_key, key)

    def generate_key_and_token(self, lifetime, valid=True):
        self.update_keys()
        return WebServerHandler.generate_token(self._key, lifetime, valid)

    def parse_jwk(self, jwk_bytes):
        return jwk.JWK(**json.loads(jwk_bytes))

    def valid_post_data_jwt_bearer(self, post_data):
        if self.public_key is None:
            self.send_error(500,
                            'public key is missing')
            return False

        scope = post_data.get('scope', None)
        if scope is not None and scope[0] not in VALID_SCOPES:
            self.send_error(400,
                            'Invalid scope \"%s\", scope should be one of %s' %
                            (scope[0], VALID_SCOPES))
            return False

        assertion = post_data.get('assertion', None)
        if assertion is None:
            self.send_error(400,
                            'assertion field is required in data')
            return False

        assertion = assertion[0]
        try:
            jwt_assertion = jwt.JWT()
            jwt_assertion.deserialize(assertion, key=self.public_key)
            claims = json.loads(jwt_assertion.claims)
            return 'sub' in claims and len(claims['sub']) > 0
        except Exception as e:
            self.send_error(400,
                            'Invalid assertion: %s' % str(e))

        return False

    def valid_post_data(self, post_data, has_authorization=True):
        if post_data is None:
            self.send_error(400,
                            'grant_type field is required')
            return False

        post_data = post_data.decode("utf-8")
        parsed_post_data = urllib.parse.parse_qs(post_data)
        if 'grant_type' in parsed_post_data \
            and parsed_post_data['grant_type'][0] == \
                WebServerHandler.JWT_BEARER_GRANT_TYPE:
            return self.valid_post_data_jwt_bearer(parsed_post_data)

        # Authorization header is required for client_credentials
        # grant type
        if not has_authorization:
            self.send_error(400, 'Authorization field is required')
            return False

        if post_data == "grant_type=client_credentials":
            return True

        if not post_data.startswith("grant_type=client_credentials&scope="):
            self.send_error(400,
                            'format of data should be grant_type='
                            'client_credentials&scope=scope_value')
            return False

        index_begin_scope = len("grant_type=client_credentials&scope=")
        scope = post_data[index_begin_scope:]
        if scope not in VALID_SCOPES:
            self.send_error(400,
                            'Invalid scope, scope should be one of %s' %
                            VALID_SCOPES)
            return False

        return True

    def generate_valid_token_for_client(self):
        """
        Example usage:
        curl \
        -X POST \
        --url localhost:PORT/retrieve \
        -H "Accept: application/json" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Authorization: Basic LW4gYWJjMTIzOlMzY3IzdCEK \
            (base64 string generated from CLIENT_ID:CLIENT_SECRET)"
        -d "grant_type=client_credentials&scope=test-scope"
        """
        if self.headers.get('Content-Length', None) is None:
            self.send_error(400, 'Content-Length field is required')
            return

        if self.headers.get('Content-Type', None) is None:
            self.send_error(400, 'Content-Type field is required')
            return

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        has_authorization = 'Authorization' in self.headers

        if self.headers.get('Accept', None) != "application/json":
            self.send_error(400, 'Accept field should be "application/json"')
            return

        if not self.valid_post_data(post_data, has_authorization):
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        token = self.generate_key_and_token(60)
        self.wfile.write(json.dumps(token, indent=4).encode())

    def generate_badformat_token_for_client(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        token = self.generate_key_and_token(30, False)
        self.wfile.write(json.dumps(token, indent=4).encode())

    def generate_expired_token_for_client(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        token = self.generate_key_and_token(-1)
        self.wfile.write(json.dumps(token, indent=4).encode())

    def do_POST(self):
        if self.path.endswith("/retrieve"):
            self.generate_valid_token_for_client()
        elif self.path.endswith("/retrieve/badformat"):
            self.generate_badformat_token_for_client()
        elif self.path.endswith("/retrieve/expire"):
            self.generate_expired_token_for_client()
        else:
            self.send_error(404, 'URL is not valid: %s' % self.path)


class OauthbearerOIDCHttpServer():
    def run_http_server(self, port, client_public_key_path=None):
        client_public_key = None
        if client_public_key_path:
            with open(client_public_key_path, 'r') as public_key:
                client_public_key = public_key.read()
        handler = WebServerHandler(client_public_key)
        server = HTTPServer(('localhost', port), handler)
        server.serve_forever()


class OauthbearerOIDCApp (trivup.App):
    """ Oauth/OIDC app, run a http server """

    def __init__(self, cluster, conf=None, on=None):
        """
        @param cluster     Current cluster.
        @param conf        Configuration dict.
               port        Port at which OauthbearerOIDCApp should be bound
                           (optional). A (random) free port will be chosen
                           otherwise.
        @param on          Node name to run on.
        """
        super(OauthbearerOIDCApp, self).__init__(cluster, conf=conf, on=on)
        public_key, key = WebServerHandler.generate_public_key()
        random_bytes = os.urandom(8)
        private_key_password = base64.b64encode(random_bytes)
        public_key_file_path = None
        private_key_file_path = None
        private_key_encrypted_file_path = None
        with (tempfile.NamedTemporaryFile(delete=False) as public_key_file,
              tempfile.NamedTemporaryFile(delete=False) as private_key_file,
              tempfile.NamedTemporaryFile(delete=False)
                as private_key_file_encrypted):

            public_key_file.write(str(public_key).encode())
            public_key_file_path = public_key_file.name

            private_key_file.write(key.export_to_pem(private_key=True,
                                                     password=None))
            private_key_file_path = private_key_file.name

            private_key_file_encrypted.write(key.export_to_pem(
                private_key=True,
                password=private_key_password))
            private_key_encrypted_file_path = private_key_file_encrypted.name

        self.conf['port'] = trivup.TcpPortAllocator(self.cluster).next(
            self, port_base=self.conf.get('port', None))
        self.conf['valid_url'] = 'http://localhost:%d/retrieve' % \
            self.conf['port']
        self.conf['badformat_url'] = 'http://localhost:%d/retrieve/badformat' \
            % self.conf['port']
        self.conf['expired_url'] = 'http://localhost:%d/retrieve/expire' % \
            self.conf['port']
        self.conf['jwks_url'] = 'http://localhost:%d/keys' % self.conf['port']
        self.conf['sasl_oauthbearer_method'] = 'OIDC'
        self.conf['sasl_oauthbearer_client_id'] = '123'
        self.conf['sasl_oauthbearer_client_secret'] = 'abc'
        self.conf['sasl_oauthbearer_client_private_key_path'] = \
            private_key_file_path
        self.conf['sasl_oauthbearer_client_private_key_encrypted_path'] = \
            private_key_encrypted_file_path
        self.conf['sasl_oauthbearer_client_private_key_password'] = \
            private_key_password
        self.conf['sasl_oauthbearer_client_public_key_path'] = \
            public_key_file_path
        self.conf['sasl_oauthbearer_scope'] = 'test'
        self.conf['sasl_oauthbearer_extensions'] = \
            'ExtensionworkloadIdentity=develC348S,Extensioncluster=lkc123'

    def start_cmd(self):
        return "python3 -m trivup.apps.OauthbearerOIDCApp --port %d " \
            "--client-public-key %s" \
               % (self.conf['port'],
                  self.conf['sasl_oauthbearer_client_public_key_path'])

    def operational(self):
        self.dbg('Checking if %s is operational' % self.get('valid_url'))
        try:
            r = requests.get(self.get('valid_url'))
            if r.status_code == 200:
                return True
            raise Exception('status_code %d' % r.status_code)
        except Exception as e:
            self.dbg('%s check failed: %s' % (self.get('valid_url'), e))
            return False

    def deploy(self):
        pass


def client_authentication_test_metadata(port, test_client_authentication_type):
    if test_client_authentication_type != 'metadata_authentication_azure_imds':
        raise Exception('Invalid test_client_authentication_type value: %s' %
                        test_client_authentication_type)

    bearer_token = requests.get(
        f'http://localhost:{port}/retrieve',
        params={'__metadata_authentication_type': 'azure_imds',
                'client_id': '1234-abcd',
                'resource': 'api://1234-abcd',
                'api-version': '2021-01-01'},
        headers={'Accept': 'application/json', 'Metadata': 'true'}).text
    print(bearer_token)


def client_authentication_test(port, test_client_authentication_type):
    if test_client_authentication_type.startswith('metadata_authentication'):
        return \
            client_authentication_test_metadata(port,
                                                test_client_authentication_type
                                                )

    if test_client_authentication_type == 'private_key_encrypted':
        client_private_key_encrypted_path = os.environ[
            'OAUTHBEARER_CLIENT_PRIVATE_KEY_ENCRYPTED']
        client_private_key_password = os.environ[
            'OAUTHBEARER_CLIENT_PRIVATE_KEY_PASSWORD']
        with open(client_private_key_encrypted_path, 'rb') as private_key_file:
            private_key = jwk.JWK.from_pem(
                private_key_file.read(),
                password=client_private_key_password.encode())
    elif test_client_authentication_type == 'private_key_plaintext':
        client_private_key_path = os.environ['OAUTHBEARER_CLIENT_PRIVATE_KEY']
        with open(client_private_key_path, 'rb') as private_key_file:
            private_key = jwk.JWK.from_pem(
                private_key_file.read(),
                password=None)
    else:
        raise Exception('Invalid test_client_authentication_type value: %s' %
                        test_client_authentication_type)

    assertion_token = WebServerHandler.generate_token(
        private_key, 60, True)['access_token']
    post_data = urllib.parse.urlencode(
        {'grant_type': WebServerHandler.JWT_BEARER_GRANT_TYPE,
         'assertion': assertion_token})
    bearer_token = requests.post(
        f'http://localhost:{port}/retrieve',
        data=post_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                 'Accept': 'application/json'}).text
    print(bearer_token)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Trivup Oauthbearer OIDC \
                                                  HTTP server')
    parser.add_argument('--port', type=int, dest='port',
                        required=True,
                        help='Port at which OauthbearerOIDCApp \
                              should be bound')
    parser.add_argument('--client-public-key', type=str,
                        dest='client_public_key',
                        required=False,
                        help=('Public key path for authentication '
                              'with assertions'))
    parser.add_argument('--test-client-authentication',
                        choices=['private_key_encrypted',
                                 'private_key_plaintext',
                                 'metadata_authentication_azure_imds'],
                        default=None,
                        required=False,
                        help=('Calls the server and authenticates using'
                              'the environment variables'))
    args = parser.parse_args()

    if args.test_client_authentication:
        client_authentication_test(args.port, args.test_client_authentication)
    else:
        http_server = OauthbearerOIDCHttpServer()
        http_server.run_http_server(args.port, args.client_public_key)
