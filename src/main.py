"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""

import email
import os
import json
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from logging import FileHandler,WARNING
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Person, TextFile
#from models import Person

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

from ratelimiter import RateLimiter

app = Flask(__name__)
file_handler = FileHandler('errorlog.txt')
file_handler.setLevel(WARNING)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@RateLimiter(max_calls=10, period=1)
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@RateLimiter(max_calls=10, period=1)
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@RateLimiter(max_calls=10, period=1)
@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=True)

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@RateLimiter(max_calls=10, period=1)
@app.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    person = Person.query.filter_by(email=email).one_or_none()
    if not person or not person.check_password(password):
        return jsonify("Wrong email or password"), 401

    # Notice that we are passing in the actual sqlalchemy user object here
    access_token = create_access_token(identity=person)
    return jsonify(access_token=access_token)


@RateLimiter(max_calls=10, period=1)
@app.route("/textfile", methods=["GET", "POST"])
@jwt_required()
def textfile():
    if request.method == 'GET':
        files = TextFile.query.all()
        values = []
        for item in range(len(files)):
            values.append({'list position': item, 'persons id': files[item].id, 'ip': files[item].ip, "update feed": files[item].update_feed, "url": files[item].url, "file text": files[item].text}) 
        return values

    if request.method == 'POST':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'update_feed' not in body:
            raise APIException('You need to specify the update_feed',jsonify(body.to_dict()), body.status_code, status_code=400)
        if 'url' not in body:
            raise APIException('You need to specify the url', status_code=400)
        if 'textfile' not in body:
            raise APIException('You need to specify the textfile', status_code=400)
        #if 'ip' not in body:
            #raise APIException('You need to specify the ip', status_code=400)
        #current_identity = get_jwt_identity()
        #current_email = Person.serialize(current_user)
        #payload = current_email
        #payload.update({'current_identity' : current_identity})
        try:
            #ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            print(body)
            put_payload = TextFile(Person(person=body['person_id']), ip="0.0.0.0", url=body['url'], update_feed=body['update_feed'], text=body['textfile'])
            db.session.add(put_payload)
            db.session.commit()

            return jsonify({
            "request":body}), 200
        except Exception as error:
            print(repr(error))
            return "!!!!" + {'args':error.args,'error':error}

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@RateLimiter(max_calls=10, period=1)
@app.route("/protected", methods=["GET", "POST", "PUT"])
@jwt_required()
def protected():
    

    if request.method == 'GET':
        # Access the identity of the current user with get_jwt_identity
        current_identity = get_jwt_identity()
        current_email = Person.serialize(current_user)
        payload = current_email
        payload.update({'current_identity' : current_identity})
        return jsonify(payload), 200
    

    if request.method == 'POST':
        body = request.get_json()

        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'email' not in body:
            raise APIException('You need to specify the email', status_code=400)
        if 'password' not in body:
            raise APIException('You need to specify the password', status_code=400)
        if 'roles' not in body:
            raise APIException('You need to specify the role', status_code=400)

        tmp_salt = Person.generate_salt()
        print("tmp_salt - " + tmp_salt)
        tmp_hash = Person.generate_hash(plain_password=body['password'], password_salt=tmp_salt)
        print("tmp_hash - " + tmp_hash)
        # at this point, all data has been validated, we can proceed to search and update db
        put_payload = Person(email=body['email'], roles=body['roles'], password=tmp_hash, salt=tmp_salt)
        db.session.add(put_payload)
        db.session.commit()
        return {
                "email":body['email'],
                "roles":body['roles'],
                "password":body['password'],
                #"password hashed":tmp_hash,
                #"salt":tmp_salt
            }, 200

    if request.method == 'PUT':
        body = request.get_json()

        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'email' not in body:
            raise APIException('You need to specify the email', status_code=400)
        if 'salt' not in body:
            raise APIException('You need to specify the salt', status_code=400)
        if 'password' not in body:
            raise APIException('You need to specify the password', status_code=400)
        if 'roles' not in body:
            raise APIException('You need to specify the role', status_code=400)

        
        # at this point, all data has been validated

        # converting password to hash for comparison
        tmp_user_hashed_password = Person.generate_hash(plain_password=body['password'], password_salt=body['salt'])

        # check db for user request
        try:
            db_query_results = Person.query.filter_by(email=str(body['email']))
            try:
                if tmp_user_hashed_password != db_query_results[0].password or \
                    body['roles'] != db_query_results[0].roles:

                    # found new data update db
                    db_query_results[0].password = tmp_user_hashed_password
                    db_query_results[0].salt = body['salt']
                    db_query_results[0].roles = body['roles']
                    db.session.commit()

                    return {
                        'status':'db successfully updated', 
                        'request':body
                        }, 200

            # requested user data not found
            except:
                raise APIException({
                'issue':'PUT request failed - no new data',
                'request':body, 
                'hashed user password':tmp_user_hashed_password,
                'db request id':db_query_results[0].id,
                'db request email':db_query_results[0].email,
                'db request password':db_query_results[0].password,
                'db results - roles':db_query_results[0].roles},
                status_code=400)
        except:
            # error send requested and retrieved data
            raise APIException({
                'issue':'PUT request failed - user data not found',
                'request':body, 
                'hashed user password':tmp_user_hashed_password,
                "salt":body['salt'],
                'db request id':db_query_results[0].id,
                'db request email':db_query_results[0].email,
                'db request password':db_query_results[0].password,
                'db results - roles':db_query_results[0].roles},
                status_code=400)



# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(Person):
    return Person.id

# Register a callback function that loads a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return Person.query.filter_by(id=identity).one_or_none()

if __name__ == "__main__":
    app.run()
