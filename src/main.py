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
from xml.sax.saxutils import escape

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


@app.route('/feeds', methods=['GET', 'POST', 'PUT', 'DELETE'])
@requires_auth
def feeds():
    try:
        user = get_or_create_user()

        if request.method == 'GET':
            # Fetch feeds and their user-specific properties
            feeds = (
                db.session.query(Feed, UserFeed)
                .join(UserFeed, UserFeed.feed_id == Feed.id)
                .filter(UserFeed.user_id == user.id)
            ).all()

            feeds_data = [
                {
                    'id': feed.id,
                    'url': feed.url,
                    'public_token': feed.public_token,
                    'save_all_new_stories': user_feed.save_all_new_stories,
                    'is_following': user_feed.is_following,
                    'created_at': feed.created_at,
                    'updated_at': feed.updated_at,
                }
                for feed, user_feed in feeds
            ]
            return jsonify({'feeds': feeds_data}), 200

        elif request.method == 'POST':
            # Add a new feed
            data = request.get_json()
            url = data.get('url')

            if not validate_url(url):
                return jsonify({'error': 'Invalid URL'}), 400

            # Check if the feed already exists for this user
            existing_feed = (
                db.session.query(Feed, UserFeed)
                .join(UserFeed, UserFeed.feed_id == Feed.id)
                .filter(UserFeed.user_id == user.id, Feed.url == url)
                .first()
            )
            if existing_feed:
                return jsonify({'message': 'Feed already exists'}), 409

            stories, raw_xml = fetch_rss_feed(url)
            new_feed = Feed(user_id=user.id, url=url, raw_xml=raw_xml)
            db.session.add(new_feed)
            db.session.flush()  # Ensure `new_feed.id` is available

            user_feed = UserFeed(user_id=user.id, feed_id=new_feed.id, is_following=True)
            db.session.add(user_feed)

            for story_data in stories:
                db.session.add(Story(feed_id=new_feed.id, data=story_data))

            db.session.commit()
            return jsonify({'message': 'Feed imported successfully', 'feed_id': new_feed.id}), 201

        elif request.method == 'PUT':
            # Update feed properties
            data = request.get_json()
            feed_id = data.get('id')
            print(f"data = {data}, feed_id = {feed_id}")

            # Fetch the UserFeed record
            user_feed = UserFeed.query.filter_by(user_id=user.id, feed_id=feed_id).first()
            if not user_feed:
                return jsonify({'error': 'UserFeed not found for the given user and feed'}), 404

            # Update fields if provided
            if 'save_all_new_stories' in data:
                user_feed.save_all_new_stories = data['save_all_new_stories']
                print(f"Updated save_all_new_stories: {user_feed.save_all_new_stories}")
            if 'is_following' in data:
                user_feed.is_following = data['is_following']
                print(f"Updated is_following: {user_feed.is_following}")

            # Fetch the Feed record to update public_token if necessary
            feed = Feed.query.filter_by(id=feed_id).first()
            if not feed:
                return jsonify({'error': 'Feed not found'}), 404

            if 'public_token' in data:
                if data['public_token'] == "GENERATE":
                    feed.generate_public_token()
                    print(f"Updated public_token: {feed.public_token}")
                else:
                    feed.public_token = None

            # Commit the changes
            try:
                print(f"Before commit: save_all_new_stories={user_feed.save_all_new_stories}, is_following={user_feed.is_following}")
                db.session.commit()
                print("After commit: Changes committed successfully.")
                return jsonify({'message': 'Feed updated successfully'}), 200
            except Exception as e:
                db.session.rollback()
                print(f"Database commit failed: {e}")
                return jsonify({'error': str(e)}), 500


        elif request.method == 'DELETE':
            # Delete a feed
            data = request.get_json()
            feed_id = data.get('feed_id')

            if not feed_id:
                return jsonify({'error': 'Feed ID is required'}), 400

            user_feed = UserFeed.query.filter_by(user_id=user.id, feed_id=feed_id).first()
            if not user_feed:
                return jsonify({'error': 'Feed not found or not authorized'}), 404

            # Delete the UserFeed and associated Feed if no other users are linked
            feed = Feed.query.filter_by(id=feed_id).first()
            db.session.delete(user_feed)
            if not UserFeed.query.filter_by(feed_id=feed_id).first():
                db.session.delete(feed)

            db.session.commit()
            return jsonify({'message': 'Feed deleted successfully'}), 200

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



@app.route('/stories', methods=['GET', 'POST', 'DELETE'])
@requires_auth
def handle_stories():
    try:
        user = get_or_create_user()

        if request.method == 'GET':
            # Fetch stories with pagination
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 10))
            feed_id = request.args.get('feed_id')

            stories_query = Story.query
            if feed_id:
                stories_query = stories_query.filter_by(feed_id=feed_id)

            total_stories = stories_query.count()
            stories = stories_query.offset((page - 1) * limit).limit(limit).all()

            stories_data = []
            for story in stories:
                user_story = UserStory.query.filter_by(user_id=user.id, story_id=story.id).first()
                stories_data.append({
                    'id': story.id,
                    'data': story.data,
                    'is_saved': user_story.is_saved if user_story else False,
                    'is_watched': user_story.is_watched if user_story else False
                })

            return jsonify({
                'stories': stories_data,
                'pagination': {
                    'current_page': page,
                    'page_size': limit,
                    'total_count': total_stories,
                    'total_pages': (total_stories + limit - 1) // limit,
                }
            }), 200

        elif request.method == 'POST':
            # Add a new story
            data = request.get_json()
            feed_id = data.get('feed_id')
            story_data = data.get('data')

            if not feed_id or not story_data:
                return jsonify({'error': 'Feed ID and story data required'}), 400

            new_story = Story(feed_id=feed_id, data=story_data)
            db.session.add(new_story)
            db.session.commit()
            return jsonify({'message': 'Story added successfully', 'story_id': new_story.id}), 201

        elif request.method == 'DELETE':
            data = request.get_json()
            story_ids = data.get('story_ids')

            # Validate input
            if not story_ids or not isinstance(story_ids, list):
                return jsonify({'error': 'A list of story IDs is required for deletion'}), 400

            print(f"[DEBUG] Received DELETE request with story_ids: {story_ids}, user_id: {user.id}")

            # Query stories directly, ensuring they belong to the user's feeds
            stories_to_delete = Story.query.filter(
                Story.id.in_(story_ids),
                Story.feed_id.in_(
                    db.session.query(UserFeed.feed_id).filter(UserFeed.user_id == user.id)
                )
            ).all()
            print(f"[DEBUG] Queried Stories for deletion: {stories_to_delete}")

            if not stories_to_delete:
                return jsonify({'error': 'No stories found or authorized for deletion'}), 404

            try:
                # Remove associated UserStory entries
                for story in stories_to_delete:
                    user_stories = UserStory.query.filter_by(story_id=story.id).all()
                    print(f"[DEBUG] UserStory entries for Story {story.id}: {user_stories}")
                    for user_story in user_stories:
                        print(f"[DEBUG] Deleting UserStory: {user_story}")
                        db.session.delete(user_story)

                # Delete the stories themselves
                for story in stories_to_delete:
                    print(f"[DEBUG] Deleting Story: {story}")
                    db.session.delete(story)

                db.session.commit()
                print(f"[SUCCESS] Stories and associated UserStory entries deleted successfully: {story_ids}")
                return jsonify({'message': 'Stories deleted successfully', 'deleted_story_ids': story_ids}), 200

            except Exception as e:
                print(f"[ERROR] Exception during deletion: {e}")
                db.session.rollback()
                return jsonify({'error': str(e)}), 500

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Exception in /stories route: {e}")
        return jsonify({'error': str(e)}), 500



@app.route('/stories/<int:story_id>', methods=['PATCH'])
@requires_auth
def update_story(story_id):
    try:
        user = get_or_create_user()
        data = request.get_json()
        user_story = UserStory.query.filter_by(user_id=user.id, story_id=story_id).first()

        if not user_story:
            user_story = UserStory(user_id=user.id, story_id=story_id)
            db.session.add(user_story)

        if 'is_saved' in data:
            user_story.is_saved = data['is_saved']
        if 'is_watched' in data:
            user_story.is_watched = data['is_watched']

        db.session.commit()
        return jsonify({
            'message': 'Story updated successfully',
            'id': user_story.story_id,
            'is_saved': user_story.is_saved,
            'is_watched': user_story.is_watched
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500




def generate_dynamic_rss(feed, stories):
    """
    Dynamically generates an RSS feed XML based on the feed and its stories.
    """
    root = ET.Element('rss', version="2.0")
    channel = ET.SubElement(root, 'channel')

    # Add channel metadata
    ET.SubElement(channel, 'title').text = f"Public Feed: {escape(feed.url)}"
    ET.SubElement(channel, 'link').text = escape(feed.url)
    ET.SubElement(channel, 'description').text = "This is a dynamically generated RSS feed."

    # Add stories
    for story in stories:
        item = ET.SubElement(channel, 'item')

        # Safely extract and encode fields
        title = story.get('title', 'No Title')
        link = story.get('link', '#')
        description = story.get('description', 'No Description')
        pub_date = story.get('published', datetime.utcnow().isoformat())

        ET.SubElement(item, 'title').text = escape(title)
        ET.SubElement(item, 'link').text = escape(link)
        ET.SubElement(item, 'description').text = escape(description)
        ET.SubElement(item, 'pubDate').text = pub_date

        # Remove non-RSS-compliant fields
        # Dynamically add extra fields if necessary (only strings)
        for key, value in story.items():
            if key not in ['title', 'link', 'description', 'published'] and isinstance(value, str):
                sub_element = ET.SubElement(item, key)
                sub_element.text = escape(value)

    return ET.tostring(root, encoding='utf-8', method='xml')


@app.route('/feeds/public/<token>', methods=['GET'])
def get_public_feed(token):
    """
    Fetches a public feed and returns it as JSON or RSS-XML based on client request.
    """
    try:
        # Fetch the feed using the public token
        feed = Feed.query.filter_by(public_token=token).first()

        if not feed:
            return jsonify({'error': 'Feed not found'}), 404

        # Extract stories from the feed
        stories = [story.data for story in feed.stories]

        # Determine the response format
        format_query = request.args.get('format', '').lower()
        accept_header = request.headers.get('Accept', '')

        if format_query == 'rss' or 'application/rss+xml' in accept_header:
            # Generate RSS XML
            rss_xml = generate_dynamic_rss(feed, stories)
            return Response(rss_xml, mimetype='application/rss+xml')
        else:
            # Default to JSON
            return jsonify({
                'feed': {
                    'url': feed.url,
                    'stories': stories
                }
            }), 200

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