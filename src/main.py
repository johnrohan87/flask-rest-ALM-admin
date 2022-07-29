"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import email
import os
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Person
#from models import Person

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

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


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET", "POST", "PUT"])
@jwt_required()
def protected():
    

    if request.method == 'GET':
        # Access the identity of the current user with get_jwt_identity
        current_identity = get_jwt_identity()
        current_email = Person.serialize(current_user)
        return jsonify(logged_in_as=current_identity,email=current_email), 200
    

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
                "password hashed":tmp_hash,
                "salt":tmp_salt
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

        db_query_results = Person.query.filter_by(email=str(body['email']))

        return {
                "email":body['email'],
                "roles":body['roles'],
                "password":body['password'],
                "salt":body['salt'],
            'db request email':db_query_results[0].email
            }, 200
    else:
        raise APIException({'issue':'identical data',
            'db email':Person.query.get(body['email']),
            'db password':Person.query.get(body['password']),
            'db roles':Person.query.get(body['roles']),
            'request':body}, status_code=400)



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
