import os
import json
import base64
from logging import FileHandler, WARNING
from functools import lru_cache
from datetime import timedelta
import requests
from flask import Flask, request, jsonify, url_for, make_response, g
from flask_migrate import Migrate
from flask_cors import CORS
from jose import jwt as JOSE
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from ratelimiter import RateLimiter
import validators 
from sqlalchemy.exc import SQLAlchemyError
from auth0.authentication import GetToken
from auth0.management import Auth0
from utils import get_or_create_user, generate_sitemap, decode_jwt, APIException, requires_auth, AuthError
from admin import setup_admin
from models import db, User, Person, TextFile, FeedPost, Todo, Feed, Story
from flask_jwt_extended import (create_access_token, create_refresh_token, 
                                get_jwt_identity, get_jwt, current_user,
                                jwt_required, JWTManager)
from services import fetch_rss_feed

app = Flask(__name__)
file_handler = FileHandler('errorlog.txt')
file_handler.setLevel(WARNING)
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_CONNECTION_STRING')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['CORS_ORIGINS'] = ['*']
app.config['CORS_HEADERS'] = 'Content-Type, Authorization, application/json'
app.config['CORS_AUTOMATIC_OPTIONS'] = True

app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY')
app.config['AUTH0_DOMAIN'] = os.environ.get('AUTH0_DOMAIN')
app.config['API_AUDIENCE'] = os.environ.get('API_AUDIENCE')
jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
cors = CORS(app)
setup_admin(app)


@app.route('/import_feed', methods=['POST'])
@requires_auth
def import_feed():
    token = request.headers.get('Authorization', None).split(' ')[1]
    try:
        userinfo = g.current_user
        email = userinfo.get('https://voluble-boba-2e3a2e.netlify.app/email')
        if not email:
            raise Exception("Email not found in token")

        # Check if user exists
        user = User.query.filter_by(auth0_id=userinfo['sub']).first()
        if not user:
            # User not found, create a new user record
            user = User(
                auth0_id=userinfo['sub'],
                email=email,
                username=userinfo.get('nickname', 'Unknown'),
                password='none',  
                is_active=True
            )
            db.session.add(user)
            db.session.commit()

        data = request.get_json()
        url = data.get('url')
        
        if not validators.url(url):
            return jsonify({'error': 'Invalid URL'}), 400

        stories, raw_xml = fetch_rss_feed(url)
        feed = Feed(url=url, user_id=user.id, raw_xml=raw_xml)
        db.session.add(feed)
        db.session.commit()

        for story_data in stories:
            story = Story(
                feed_id=feed.id,
                data=story_data
            )
            db.session.add(story)
        db.session.commit()

        return jsonify({'message': 'Feed imported successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 401


@app.route('/edit_story/<int:story_id>', methods=['PUT'])
@requires_auth
def edit_story(story_id):
    try:
        userinfo = g.current_user
        user = get_or_create_user(userinfo)

        story = Story.query.get(story_id)
        if not story or story.feed.user_id != user.id:
            return jsonify({'error': 'Story not found or unauthorized'}), 404

        data = request.get_json()
        story.custom_title = data.get('custom_title', story.custom_title)
        story.custom_content = data.get('custom_content', story.custom_content)
        db.session.commit()

        return jsonify({'message': 'Story updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 401



@app.route('/user_feed', methods=['GET'])
@requires_auth
def user_feed():
    token = request.headers.get('Authorization', None).split(' ')[1]
    print('token', token)
    try:
        userinfo = g.current_user
        print('userinfo', userinfo)
        email = userinfo.get('https://voluble-boba-2e3a2e.netlify.app/email')
        if not email:
            raise Exception("Email not found in token")

        # Check if user exists
        user = User.query.filter_by(auth0_id=userinfo['sub']).first()
        if not user:
            # User not found, create a new user record
            user = User(
                auth0_id=userinfo['sub'],
                email=email,
                username=userinfo.get('nickname', 'Unknown'),
                password='none',  
                is_active=True
            )
            db.session.add(user)
            db.session.commit()

        # Fetch user's feeds
        feeds = Feed.query.filter_by(user_id=user.id).all()
        user_feed = []

        for feed in feeds:
            stories = Story.query.filter_by(feed_id=feed.id).all()
            for story in stories:
                story_data = {
                    'id': story.id,
                    'feed_id': story.feed_id,
                    'data': story.data,
                    'custom_title': story.custom_title,
                    'custom_content': story.custom_content,
                }
                user_feed.append(story_data)

        return jsonify({'feed': user_feed}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 401



@app.route('/user_stories', methods=['GET'])
@requires_auth
def user_stories():
    try:
        userinfo = g.current_user
        current_user_id = userinfo['sub']
        
        user = User.query.filter_by(auth0_id=current_user_id).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        feed_id = request.args.get('feed_id')
        if feed_id:
            feed = Feed.query.filter_by(id=feed_id, user_id=user.id).first()
            if not feed:
                return jsonify({'error': 'Feed not found or unauthorized'}), 404

            stories = Story.query.filter_by(feed_id=feed.id).all()
        else:
            feeds = Feed.query.filter_by(user_id=user.id).all()
            stories = []
            for feed in feeds:
                feed_stories = Story.query.filter_by(feed_id=feed.id).all()
                stories.extend(feed_stories)

        user_stories = []
        for story in stories:
            story_data = {
                'id': story.id,
                'feed_id': story.feed_id,
                'data': story.data,
                'custom_title': story.custom_title,
                'custom_content': story.custom_content,
                'created_at': story.created_at,
                'updated_at': story.updated_at
            }
            user_stories.append(story_data)

        return jsonify({'stories': user_stories}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/delete_stories', methods=['DELETE'])
@requires_auth
def delete_stories():
    try:
        # Get the current user
        userinfo = g.current_user
        print('g.current_user', userinfo)
        current_user_id = userinfo['sub']
        print('current_user_id', current_user_id)

        # Get the user by auth0_id
        user = User.query.filter_by(auth0_id=current_user_id).first()
        print('user', user)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get story IDs from the request body
        story_ids = request.json.get('story_ids')
        print('story_ids', story_ids)
        if not story_ids:
            return jsonify({'error': 'No story IDs provided'}), 400

        print(f"Received story IDs for deletion: {story_ids}")

        # Fetch the stories based on story IDs
        stories = Story.query.filter(Story.id.in_(story_ids)).all()
        print('stories', stories)
        if not stories:
            return jsonify({'error': 'No stories found'}), 404

        # Check if all stories belong to the current user
        for story in stories:
            feed = Feed.query.get(story.feed_id)
            print(f"Story ID: {story.id}, Feed ID: {story.feed_id}, User ID: {feed.user_id}, Current User ID: {user.id}")
            if feed.user_id != user.id:
                return jsonify({'error': f'Unauthorized: Feed user_id {feed.user_id} does not match current user_id {user.id}'}), 403

        # Delete the stories
        for story in stories:
            db.session.delete(story)
        db.session.commit()

        return jsonify({'message': 'Stories deleted successfully'}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/debug_stories', methods=['GET'])
@requires_auth
def debug_stories():
    try:
        userinfo = g.current_user
        current_user_id = userinfo['sub']
        
        print(f"Current user ID: {current_user_id}")

        # Fetch all feeds for the current user
        user = User.query.filter_by(auth0_id=current_user_id).first()
        if not user:
            print(f"User not found for auth0_id: {current_user_id}")
            return jsonify({'error': 'User not found for this auth0_id'}), 404

        feeds = Feed.query.filter_by(user_id=user.id).all()
        if not feeds:
            print(f"No feeds found for user ID: {user.id}")
            return jsonify({'error': 'No feeds found for this user'}), 404

        # Collect all stories for these feeds
        all_stories = []
        for feed in feeds:
            stories = Story.query.filter_by(feed_id=feed.id).all()
            for story in stories:
                story_data = {
                    'id': story.id,
                    'feed_id': story.feed_id,
                    'data': story.data,
                    'custom_title': story.custom_title,
                    'custom_content': story.custom_content,
                }
                all_stories.append(story_data)

        # Print the stories for debugging
        for story in all_stories:
            print(f"Story ID: {story['id']}, Feed ID: {story['feed_id']}, Data: {story['data']}")

        return jsonify({'stories': all_stories}), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/user_feed', methods=['GET'])
@requires_auth
def user_feed():
    try:
        token = request.headers.get('Authorization', None).split(' ')[1]
        print('token', token)

        userinfo = g.current_user
        print('userinfo', userinfo)

        email = userinfo.get('https://voluble-boba-2e3a2e.netlify.app/email')
        if not email:
            raise ValueError("Email not found in token")

        # Check if user exists
        user = User.query.filter_by(auth0_id=userinfo['sub']).first()
        if not user:
            print(f"User not found. Creating new user with email {email}")
            user = User(
                auth0_id=userinfo['sub'],
                email=email,
                username=userinfo.get('nickname', 'Unknown'),
                password='none',
                is_active=True
            )
            db.session.add(user)
            db.session.commit()

        # Fetch user's feeds
        feeds = Feed.query.filter_by(user_id=user.id).all()
        user_feed = []

        for feed in feeds:
            stories = Story.query.filter_by(feed_id=feed.id).all()
            for story in stories:
                story_data = {
                    'id': story.id,
                    'feed_id': story.feed_id,
                    'data': story.data,
                    'custom_title': story.custom_title,
                    'custom_content': story.custom_content,
                }
                user_feed.append(story_data)

        print(f"User feed retrieved for user {user.id}")
        return jsonify({'feed': user_feed}), 200

    except ValueError as ve:
        print(f"Validation error: {ve}")
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred.'}), 500


@app.route('/user_info', methods=['GET'])
@requires_auth
def user_info():
    userinfo = get_userinfo(request)
    user = User.query.filter_by(auth0_id=userinfo['sub']).first()
    if not user:
        print('user not found')
        print('request', request)
        return jsonify({'error': 'User not found'}), 404

    user_data = {
        'id': user.id,
        'auth0_id': user.auth0_id,
        'username': user.username,
        'feeds': []
    }

    feeds = Feed.query.filter_by(user_id=user.id).all()
    for feed in feeds:
        feed_data = {
            'id': feed.id,
            'url': feed.url,
            'raw_xml': feed.raw_xml,
            'stories': []
        }
        stories = Story.query.filter_by(feed_id=feed.id).all()
        for story in stories:
            story_data = {
                'id': story.id,
                'data': story.data,
                'custom_title': story.custom_title,
                'custom_content': story.custom_content
            }
            feed_data['stories'].append(story_data)
        user_data['feeds'].append(feed_data)

    return jsonify(user_data)

@app.errorhandler(AuthError)
def handle_auth_error(error):
    response = jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.error['description']
    })
    response.status_code = error.status_code
    return response

@app.route('/auth0protected')
def auth0protected():
    token = request.headers.get('Authorization', None)
    if not token:
        return jsonify({'message': "Authorization header is expected"}), 401
    token = token.split()[1]
    try:
        payload = decode_jwt(token)
        return jsonify({'message': "Protected content!", 'user': payload}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 401

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

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user

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

    access_token = create_access_token(identity=person, fresh=True, expires_delta=app.config["JWT_ACCESS_TOKEN_EXPIRES"])
    refresh_token = create_refresh_token(identity=person)
    response = jsonify({"access_token": access_token, "refresh_token": refresh_token, "expires_in": app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()})
    return response, 200



@RateLimiter(max_calls=10, period=1)
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        print(current_user_id)

        # Assuming current_user_id is the user's ID
        user = Person.query.filter_by(id=current_user_id).first_or_404()
        print(user)

        # Mark the new token as fresh if the previous one was fresh
        fresh = user.is_fresh
        print(fresh)

        new_access_token = create_access_token(identity=user, fresh=fresh)
        print(new_access_token)

        return jsonify({"access_token": new_access_token}), 200
    
    except Exception as error:
        print(repr(error))
        return jsonify({"error": "An unexpected error occurred", "details": repr(error)}), 500

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
        return jsonify({'id': new_todo.id, 'text': new_todo.text}), 201
    
    #if request.method == "OPTIONS": # CORS preflight
    #    return _build_cors_preflight_response(), 200
    
@RateLimiter(max_calls=10, period=1)
@app.route("/api/todos/<int:todo_id>/<string:todo_updatedText>", methods=["PUT"])
@jwt_required(fresh=True)
#@cross_origin(origin='*',headers=['Content-Type','Authorization','application/json'])
def todoAppModify(todo_id, todo_updatedText):
    user_id = get_jwt_identity()

    if request.method == 'PUT':
        todo = Todo.query.filter_by(id=todo_id, userID=user_id).first_or_404()
        todo.text = todo_updatedText  # Update the todo text with the new value from the URL path
        db.session.commit()
        return jsonify({'id': todo.id, 'text': todo.text}), 200

    
@RateLimiter(max_calls=10, period=1)
@app.route("/api/todos/<int:todo_id>", methods=["PUT", "DELETE"])
@jwt_required(fresh=True)
#@cross_origin(origin='*',headers=['Content-Type','Authorization','application/json'])
def todoAppDel(todo_id):
    user_id = get_jwt_identity()
    if request.method == 'PUT':
        todo = Todo.query.filter_by(id=todo_id, userID=user_id).first_or_404()
        data = request.get_json()
        if 'text' in data:
            todo.text = data['text']
            db.session.commit()
            return jsonify({'id':todo.id, 'text': todo.text}), 200
        else:
            return jsonify({'error': 'Missing text field'}), 400
        
    if request.method == 'DELETE':
        print(todo_id)
        todo = Todo.query.filter_by(id=todo_id, userID=user_id).first_or_404()
        print(user_id)
        print(todo)
        print(todo.id)
        db.session.delete(todo)
        db.session.commit()
        return jsonify({'id':todo.id, 'text': todo.text}), 200

if __name__ == "__main__":
    app.run()
