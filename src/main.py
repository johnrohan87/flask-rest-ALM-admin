"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""

import email
import os
import json
from flask import Flask, request, jsonify, url_for, make_response
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS, cross_origin
from logging import FileHandler,WARNING
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User, Person, TextFile, FeedPost, Todo
#from models import Person

from flask_jwt_extended import (create_access_token, 
                                create_refresh_token, 
                                get_jwt_identity, current_user,
                                jwt_required, JWTManager)
from ratelimiter import RateLimiter
from datetime import timedelta

app = Flask(__name__)
file_handler = FileHandler('errorlog.txt')
file_handler.setLevel(WARNING)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['CORS_HEADERS'] = 'Content-Type, Authorization, application/json'

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
cors = CORS(app)
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
    if request.method == "OPTIONS": # CORS preflight
        return _build_cors_preflight_response()
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    person = Person.query.filter_by(email=email).one_or_none()
    if not person or not person.check_password(password):
        return jsonify("Wrong email or password"), 401

    # Notice that we are passing in the actual sqlalchemy user object here
    print(person)
    access_token = create_access_token(identity=person, fresh=True)
    refresh_token = create_refresh_token(identity=person)
    response = jsonify({"access_token":access_token, "refresh_token":refresh_token})
    return _corsify_actual_response(response),200



@RateLimiter(max_calls=10, period=1)
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    user = Person.get(current_user, None)

    if not user:
        return jsonify({"message": "User not found"}), 404

    # Mark the new token as fresh if the previous one was fresh
    fresh = user['is_fresh']
    new_access_token = create_access_token(identity=current_user, fresh=fresh)

    return jsonify({"access_token": new_access_token}), 200

# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@RateLimiter(max_calls=10, period=1)
@app.route("/protected", methods=["GET", "POST", "PUT"])
@jwt_required(fresh=True)
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

@RateLimiter(max_calls=10, period=1)
@app.route("/textfile", methods=["GET","PUT","POST"])
@jwt_required(fresh=True)
def textfile():
    if request.method == 'GET':
        files = TextFile.query.all()
        values = []
        for item in range(len(files)):
            values.append({'list position': item, 'persons id': files[item].id, 'ip': files[item].ip, "update feed": files[item].update_feed, "url": files[item].url, "file text": files[item].text}) 
        return jsonify(values),200
    
    if request.method == 'PUT':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'update_feed' not in body:
            raise APIException('You need to specify the update_feed', status_code=400)
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

    if request.method == 'POST':
        feedData = request.get_json()
        body = feedData['data']
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'update_feed' not in body:
            raise APIException('You need to specify the update_feed', {"data": Flask.jsonify(str(body))}, status_code=400)
        if 'url' not in body:
            raise APIException('You need to specify the url', status_code=400)
        if 'textfile' not in body:
            raise APIException('You need to specify the textfile', status_code=400)

        try:
            ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            print(body)
            put_payload = TextFile(person_id=body['person_id'], ip=ip_addr, url=body['url'], update_feed=body['update_feed'], text=body['textfile'])
            db.session.add(put_payload)
            db.session.commit()

            return jsonify({
            "request":body}), 200
        except Exception as error:
            print(repr(error))
            return "!!!!" + {'error':str(error)}
        
@RateLimiter(max_calls=10, period=1)
@app.route("/feedpost", methods=["GET","PUT"])
@jwt_required(fresh=True)
def feedpost():
    if request.method == 'GET':
        posts = FeedPost.query.all()
        values = {}
        #for item in range(len(post)):
            #values.append({'list position': item, 'id': post[item].id, 'feed_id': post[item].feed_id, "title": post[item].title, "link": post[item].link, "published": post[item].published}) 
        for post in range(len(posts)):
            srlPost = posts[post].serialize()
            values.update({post:srlPost})
        return jsonify(values),200
    if request.method == 'PUT':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'feed_id' not in body:
            raise APIException('You need to specify the feed_id', status_code=400)
        if 'title' not in body:
            raise APIException('You need to specify the textfile', status_code=400)
        if 'link' not in body:
            raise APIException('You need to specify the link', status_code=400)
        if 'published' not in body:
            raise APIException('You need to specify the published', status_code=400)
        if 'published_parsed' not in body:
            raise APIException('You need to specify the published_parsed', status_code=400)
        if 'author' not in body:
            raise APIException('You need to specify the author', status_code=400)
        if 'summary' not in body:
            raise APIException('You need to specify the summary', status_code=400)
        if 'tags' not in body:
            raise APIException('You need to specify the tags', status_code=400)

        try:
            #ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            print(body)
            put_payload = FeedPost(feed_id=body['feed_id'], title=body['title'], link=body['link'], published=body['published'], published_parsed=body['published_parsed'], author=body['author'],  summary=body['summary'],  tags=body['tags'])
            db.session.add(put_payload)
            db.session.commit()

            return jsonify({
            "request":body}), 200
        except Exception as error:
            print(repr(error))
            return ("!!!!" + repr(error))
        
@RateLimiter(max_calls=10, period=1)
@app.route("/addrss", methods=["PUT","POST"])
@jwt_required(fresh=True)
def addrss():
    if request.method == 'PUT':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'update_feed' not in body:
            raise APIException('You need to specify the update_feed', status_code=400)
        if 'url' not in body:
            raise APIException('You need to specify the url', status_code=400)
        try:
            print(" -=request below=- ")
            print(body)

            #Running FeedParser to check status of feed
            import feedparser
            feed = feedparser.parse(body['url'])

            ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            print("adding to TextFile now")
            put_payload = TextFile(person_id=body['person_id'], ip=ip_addr, url=body['url'], update_feed=body['update_feed'], text=({"status":feed.status,"bozo":feed.bozo,"encoding":feed.encoding}))
            db.session.add(put_payload)
            db.session.commit()
            db.session.refresh(put_payload)
            print(repr(put_payload.serialize()))
            tmpTargetTextFile = put_payload.serialize()['file id']
            print('tmpTargetTextFile - '+ str(tmpTargetTextFile))

            for item in feed.entries:
                print("entrie -= "+repr(item)+" =-")
                if item.has_key('title'): tmpTitle = item.title 
                else: tmpTitle = "No Title"
                print(tmpTitle+" - "+str(type(tmpTitle)))
                if item.has_key('link'): tmpLink = json.dumps(item.link)
                else: tmpLink = "No Link"
                print(tmpLink+" - "+str(type(tmpLink)))
                if item.has_key('published'): tmpPublished = item.published 
                else: tmpPublished = "No Published"
                print(tmpPublished+" - "+str(type(tmpPublished)))
                if item.has_key('published_parsed'): tmpPublishedParsed = str(item.published_parsed) 
                else: tmpPublishedParsed = "No Published_Parsed"
                print(tmpPublishedParsed+" - "+str(type(tmpPublishedParsed)))
                if item.has_key('author'): tmpAuthor = item.author 
                else: tmpAuthor = "No Author"
                print(tmpAuthor+" - "+str(type(tmpAuthor)))
                if item.has_key('summary'): tmpSummary = item.summary 
                else: tmpSummary = "No Summary"
                print(tmpSummary+" - "+str(type(tmpSummary)))
                if item.has_key('tags'): tmpTags = json.dumps(item.tags)
                else: tmpTags = "No Tags"
                print(tmpTags+" - "+str(type(tmpTags)))

                put_payload = FeedPost(feed_id=tmpTargetTextFile, title=tmpTitle, link=tmpLink, published=tmpPublished, published_parsed=tmpPublishedParsed, author=tmpAuthor, summary=tmpSummary, tags=tmpTags)
                db.session.add(put_payload)
                db.session.commit()

            return jsonify({
            "request":body,
            "response":feed}), 200
        except Exception as error:
            print(repr(error))
            return ("!!!!" + repr(error))
    if request.method == 'POST':
        body = request.get_json()
        if body is None:
            raise APIException("You need to specify the request body as a json object", status_code=400)
        if 'update_feed' not in body:
            raise APIException('You need to specify the update_feed', status_code=400)
        if 'url' not in body:
            raise APIException('You need to specify the url', status_code=400)
        try:
            print(" -=request below=- ")
            print(body)

            #Running FeedParser to check status of feed
            import feedparser
            feed = feedparser.parse(body['url'])
            feedKeys = list(feed)
            feedLen = len(feed.entries)
            print(feedKeys)

            return jsonify({
            "request":body,
            "response":feed,
            "feedKeys":feedKeys,
            "feedLen":feedLen
            }), 200
        except Exception as error:
            print(repr(error))
            return ("!!!!" + repr(error))

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
    
# adding todo app
@RateLimiter(max_calls=10, period=1)
@app.route("/api/todos", methods=["GET", "POST"])
@jwt_required(fresh=True)
#@cross_origin(origin='*',headers=['Content-Type','Authorization'])
def todoApp():
    if request.method == 'GET':
        user_id = get_jwt_identity()
        todos = Todo.query.filter_by(userID=user_id).all()
        todos_list = [{'id': todo.id, 'text': todo.text} for todo in todos]
        return jsonify(todos_list), 200
    
    if request.method == 'POST':
        user_id = get_jwt_identity()
        data = request.json
        print(data)
        new_todo = Todo(text=data['text'], userID=user_id)
        print(new_todo)
        db.session.add(new_todo)
        db.session.commit()
        return _corsify_actual_response(jsonify({'id': new_todo.id, 'text': new_todo.text})), 201
    
@RateLimiter(max_calls=10, period=1)
@app.route("/api/todos/<int:todo_id>/<string:todo_updatedText>", methods=["PUT", "DELETE", "OPTIONS"])
@jwt_required(fresh=True)
@cross_origin(origin='*',headers=['Content-Type','Authorization','application/json'])
def todoAppModify(todo_id, todo_updatedText):
    user_id = get_jwt_identity()

    if request.method == 'PUT':
        todo = Todo.query.filter_by(id=todo_id, userID=user_id).first_or_404()
        todo.text = todo_updatedText  # Update the todo text with the new value from the URL path
        db.session.commit()
        return jsonify({'id': todo.id, 'text': todo.text}), 200


    if request.method == 'DELETE':
        todo = Todo.query.filter_by(id=todo_id, userID=user_id).first_or_404()
        print(user_id)
        print(todo)
        print(todo.id)
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'id':todo.id, 'text': todo.text}), 200
    
    if request.method == "OPTIONS": # CORS preflight
        return _build_cors_preflight_response()
    
def _build_cors_preflight_response():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response

def _corsify_actual_response(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

if __name__ == "__main__":
    app.run()
