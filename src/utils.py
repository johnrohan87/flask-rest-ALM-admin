import requests
import os
import json
import base64
from flask import request, g, url_for
from functools import wraps, lru_cache
from jose import jwk, jwt, jwe as JOSE
from jose.utils import base64url_decode
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError



class APIException(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(defaults) >= len(arguments)

def generate_sitemap(app):
    links = ['/admin/']
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            if "/admin/" not in url:
                links.append(url)

    links_html = "".join(["<li><a href='" + y + "'>" + y + "</a></li>" for y in links])
    return """
        <div style="text-align: center;">
        <img style="max-height: 80px" src='https://ucarecdn.com/3a0e7d8b-25f3-4e2f-add2-016064b04075/rigobaby.jpg' />
        <h1>Rigo welcomes you to your API!!</h1>
        <p>API HOST: <script>document.write('<input style="padding: 5px; width: 300px" type="text" value="'+window.location.href+'" />');</script></p>
        <p>Start working on your project by following the <a href="https://github.com/4GeeksAcademy/flask-rest-hello/blob/master/docs/_QUICK_START.md" target="_blank">Quick Start</a></p>
        <p>Remember to specify a real endpoint path like: </p>
        <ul style="text-align: left;">"""+links_html+"</ul></div>"


AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN')
AUTH0_AUDIENCE = os.environ.get('AUTH0_AUDIENCE')
ALGORITHMS = ['RS256']

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

def get_token_auth_header():
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()

    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with Bearer.'
        }, 401)
    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)
    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be Bearer token.'
        }, 401)

    token = parts[1]
    return token

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = requests.get(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
        jwks = jsonurl.json()
        header = json.loads(base64_url_decode(token.split('.')[0]).decode('utf-8'))
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
        if rsa_key:
            try:
                payload = decode_jwt(token, AUTH0_DOMAIN, AUTH0_AUDIENCE)
                g.current_user = payload
                return f(*args, **kwargs)
            except Exception as e:
                raise AuthError({
                    'code': 'invalid_token',
                    'description': str(e)
                }, 401)
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to find appropriate key'
        }, 401)
    return decorated

def decode_jwt_token(token):
    try:
        auth0_domain = app.config["AUTH0_DOMAIN"]
        api_audience = app.config["API_AUDIENCE"]
        return decode_jwt(token, auth0_domain, api_audience)
    except Exception as e:
        raise Exception(f"Error decoding token: {str(e)}")

def decode_jwt(token, auth0_domain, api_audience):
    try:
        # Decode the JWT header manually
        header = json.loads(base64_url_decode(token.split('.')[0]).decode('utf-8'))
        kid = header['kid']
        print(f"Decoded JWT Header: {header}")
        
        # Fetch the JWKS
        jwks = get_jwks(auth0_domain)
        print(f"JWKS: {json.dumps(jwks, indent=2)}")
        
        # Find the key that matches the kid
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == kid:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }
                break
        
        if not rsa_key:
            raise Exception("No appropriate keys found")
        
        # Decode the token
        payload = JOSE.decode(
            token,
            rsa_key,
            algorithms=['RS256'],
            audience=api_audience,
            issuer=f'https://{auth0_domain}/'
        )

        print(f"Decoded Payload: {json.dumps(payload, indent=2)}")
        
        # Check audience
        if api_audience not in payload['aud']:
            print(f"Audience mismatch: {payload['aud']} != {api_audience}")
            raise Exception("Invalid claims: incorrect audience")

        return payload

    except ExpiredSignatureError:
        raise Exception("Token expired")
    except JWTClaimsError:
        raise Exception("Invalid claims")
    except JWTError as e:
        raise Exception(f"Unable to parse token: {str(e)}")
    except Exception as e:
        raise Exception(f"Error decoding token: {str(e)}")

def get_jwks(auth0_domain):
    jwks_url = f'https://{auth0_domain}/.well-known/jwks.json'
    response = requests.get(jwks_url)
    response.raise_for_status()
    return response.json()

def base64_url_decode(input):
    rem = len(input) % 4
    if rem > 0:
        input += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input)