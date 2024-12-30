import os
from datetime import datetime, timezone
from logging import FileHandler, WARNING
from datetime import timedelta
from flask import Flask, request, jsonify, g, Response
from flask_migrate import Migrate
from flask_cors import CORS
from jose import jwt as JOSE
from throttler import Throttler
from sqlalchemy.exc import SQLAlchemyError
from auth0.authentication import GetToken
from auth0.management import Auth0



from flask_jwt_extended import (current_user, JWTManager)
from services import fetch_rss_feed
from admin import setup_admin
from utils import get_or_create_user, generate_sitemap, decode_jwt, APIException, requires_auth, AuthError, validate_url
from models import db, User, UserFeed, Person, TextFile, FeedPost, Todo, Feed, Story, UserStory
import xml.etree.ElementTree as ET

throttler = Throttler(rate_limit=10, period=60)

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

API_BASE_URL = os.environ.get('API_BASE_URL')


jwt = JWTManager(app)

MIGRATE = Migrate(app, db)
db.init_app(app)
cors = CORS(app)
setup_admin(app)


@app.route('/feeds', methods=['GET'])
@requires_auth
def get_feeds():
    try:
        user = get_or_create_user()

        # Fetch feeds and their user-specific properties
        feeds = (
            db.session.query(Feed, UserFeed)
            .join(UserFeed, UserFeed.feed_id == Feed.id)
            .filter(UserFeed.user_id == user.id)
        ).all()

        # Construct the response
        feeds_data = [
            {
                'id': feed.id,
                'url': feed.url,
                'public_token': feed.public_token,
                'save_all_new_stories': user_feed.save_all_new_stories,
                'is_following': user_feed.is_following,
            }
            for feed, user_feed in feeds
        ]

        return jsonify({'feeds': feeds_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/feeds', methods=['POST'])
@requires_auth
def import_feed():
    try:
        user = get_or_create_user()
        data = request.get_json()
        url = data.get('url')

        if not validate_url(url):
            return jsonify({'error': 'Invalid URL'}), 400

        existing_feed = Feed.query.filter_by(user_id=user.id, url=url).first()

        if existing_feed:
            return jsonify({'message': 'Feed already exists'}), 409

        stories, raw_xml = fetch_rss_feed(url)
        new_feed = Feed(user_id=user.id, url=url, raw_xml=raw_xml)
        db.session.add(new_feed)
        for story_data in stories:
            db.session.add(Story(feed_id=new_feed.id, data=story_data))
        db.session.commit()
        return jsonify({'message': 'Feed imported successfully', 'feed_id': new_feed.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/feeds', methods=['PUT'])
@requires_auth
def update_feed():
    try:
        user = get_or_create_user()
        data = request.get_json()
        feed_id = data.get('id')

        feed = Feed.query.filter_by(id=feed_id, user_id=user.id).first()
        if not feed:
            return jsonify({'error': 'Feed not found'}), 404

        # Update fields if provided
        if 'save_all_new_stories' in data:
            feed.save_all_new_stories = data['save_all_new_stories']
        if 'is_following' in data:
            feed.is_following = data['is_following']
        if 'public_token' in data:
            if data['public_token'] == "GENERATE":
                feed.generate_public_token()
            else:
                feed.public_token = None

        db.session.commit()
        return jsonify({'message': 'Feed updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/feeds/preview', methods=['POST'])
@requires_auth
def preview_feed():
    try:
        data = request.get_json()
        url = data.get('url')

        if not validate_url(url):
            return jsonify({'error': 'Invalid URL'}), 400

        stories, raw_xml = fetch_rss_feed(url)
        # Extract dynamic fields for frontend rendering
        sample_story = stories[0] if stories else {}
        fields = list(sample_story.keys())

        return jsonify({
            'metadata': {
                'title': sample_story.get('title', 'No Title'),
                'description': sample_story.get('description', 'No Description'),
                'fields': fields,  # Include available fields
            },
            'stories': stories[:10],  # Limit to the first 10 stories
            'raw_xml': raw_xml.decode('utf-8'),  # Include raw XML if needed
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/stories', methods=['GET'])
@requires_auth
def get_stories():
    try:
        user = get_or_create_user()
        feed_id = request.args.get('feed_id')
        if feed_id:
            stories = Story.query.filter_by(feed_id=feed_id).all()

        else:
            feeds = Feed.query.filter_by(user_id=user.id).all()
            feed_ids = [f.id for f in feeds]
            stories = Story.query.filter(Story.feed_id.in_(feed_ids)).all()
        stories_data = [{'id': s.id, 'data': s.data} for s in stories]
        return jsonify({'stories': stories_data}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stories', methods=['POST'])
@requires_auth
def add_story():
    try:
        user = get_or_create_user()
        data = request.get_json()
        feed_id = data.get('feed_id')
        story_data = data.get('data')

        if not feed_id or not story_data:
            return jsonify({'error': 'Feed ID and story data required'}), 400

        new_story = Story(feed_id=feed_id, data=story_data)
        db.session.add(new_story)
        db.session.commit()
        return jsonify({'message': 'Story added successfully', 'story_id': new_story.id}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/feeds/public/<token>', methods=['GET'])
def get_public_feed(token):
    try:
        feed = Feed.query.filter_by(public_token=token).first()

        if not feed:
            return jsonify({'error': 'Feed not found'}), 404

        stories = [{'id': s.id, 'data': s.data} for s in feed.stories]
        return jsonify({'feed': {'url': feed.url, 'stories': stories}}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



# generate sitemap with all your endpoints

@app.route('/')
def sitemap():
    return generate_sitemap(app)


# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=True)


if __name__ == "__main__":
    app.run()
