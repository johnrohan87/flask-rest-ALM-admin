import requests
import os
import json
import base64
import re
from flask import request, g, url_for
from functools import wraps, lru_cache
from jose import jwt as JOSE
from jose.utils import base64url_decode
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from models import db, User
import xml.etree.ElementTree as ET
from urllib.parse import urlparse



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
API_AUDIENCE = os.environ.get('API_AUDIENCE')
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
        try:
            payload = decode_jwt(token, AUTH0_DOMAIN, API_AUDIENCE)
            g.current_user = payload
        except AuthError as e:
            return jsonify(e.error), e.status_code
        return f(*args, **kwargs)
    return decorated

def decode_jwt(token, auth0_domain, api_audience):
    try:
        header = JOSE.get_unverified_header(token)
        jwks = get_jwks(auth0_domain)
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
                break
        
        if not rsa_key:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find appropriate key'
            }, 401)

        payload = JOSE.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=api_audience,
            issuer=f'https://{auth0_domain}/'
        )

        return payload

    except ExpiredSignatureError:
        raise AuthError({
            'code': 'token_expired',
            'description': 'token is expired'
        }, 401)
    except JWTClaimsError:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'incorrect claims, please check the audience and issuer'
        }, 401)
    except JWTError:
        raise AuthError({
            'code': 'invalid_token',
            'description': 'token is invalid'
        }, 401)

def get_jwks(auth0_domain):
    jwks_url = f'https://{auth0_domain}/.well-known/jwks.json'
    response = requests.get(jwks_url)
    response.raise_for_status()
    return response.json()


def get_or_create_user():
    userinfo = g.current_user
    print(f"userinfo : {userinfo}")
    email = userinfo.get('https://voluble-boba-2e3a2e.netlify.app/email')
    roles = userinfo.get('https://voluble-boba-2e3a2e.netlify.app/roles', [])

    print(f"email : {email}")
    if not email:
        raise Exception("Email not found in token")

    user = User.query.filter_by(auth0_id=userinfo['sub']).first()
    if not user:

        # Set username to email if no nickname is provided
        username = userinfo.get('nickname', email)

        user = User(
            auth0_id=userinfo['sub'],
            email=email,
            username=username,
            password='none',
            is_active=True
        )
        db.session.add(user)
        db.session.commit()
        
    user.auth0_roles = roles
    return user


def fetch_rss_feed(url):
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch RSS feed: {response.status_code}")

    root = ET.fromstring(response.content)
    stories = []
    for item in root.findall('.//item'):
        story = {
            'title': item.find('title').text if item.find('title') is not None else 'No Title',
            'description': item.find('description').text if item.find('description') is not None else 'No Description',
            'link': item.find('link').text if item.find('link') is not None else '',
            # Add other fields as needed
        }
        stories.append(story)

    return stories, response.content  # Return both stories and the raw XML


def validate_url(url_str):
    """
    Validates a URL to ensure it has a valid structure.
    
    Args:
        url_str (str): The URL string to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url_str)
        # Ensure the URL has both a scheme and netloc
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def validate_email(email):
    """
    Validates an email address using a regular expression.

    Args:
        email (str): The email string to validate.

    Returns:
        bool: True if the email is valid, False otherwise.
    """
    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(email_regex, email) is not None