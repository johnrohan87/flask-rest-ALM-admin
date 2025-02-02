import os
import re
import functools
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


import json
from flask_jwt_extended import (current_user, JWTManager)
from services import fetch_rss_feed
from admin import setup_admin
from utils import get_or_create_user, generate_sitemap, decode_jwt, APIException, requires_auth, AuthError, validate_url
from models import db, User, UserFeed, Person, TextFile, FeedPost, Todo, Feed, Story, UserStory
import xml.etree.ElementTree as ET
from html import unescape
from email.utils import formatdate
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

##############################
##  ADMIN ENDPOINTS & MGMT
#############################


def admin_required(f):
    """Decorator to check if the requesting user has admin privileges."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = get_or_create_user()
        if not user or "Admin" not in user.auth0_roles:
            return jsonify({"error": "Access denied. Admin privileges required."}), 403
        return f(*args, **kwargs)
    return wrapper

@app.route('/admin/users', methods=['GET'])
@requires_auth
@admin_required
def get_all_users():
    """Returns all users (Admin only)."""
    users = User.query.all()
    return jsonify([{
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat(),
    } for user in users]), 200

@app.route('/admin/users/<int:user_id>', methods=['PATCH'])
@requires_auth
@admin_required
def update_user(user_id):
    """Update a user's details (Admin only)."""
    data = request.json
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    if 'username' in data:
        user.username = data['username']
    if 'is_active' in data:
        user.is_active = data['is_active']

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@requires_auth
@admin_required
def delete_user(user_id):
    """Delete a user (Admin only)."""
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200


# Validate URL function
def is_valid_url(url):
    url_regex = re.compile(
        r'^(https?|ftp):\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$'
    )
    return re.match(url_regex, url) is not None

# Securely parse XML
def parse_securely(xml_content):
    try:
        return ET.fromstring(xml_content)
    except ET.ParseError:
        return None
    

##############################
##  FEEDS MGMT
#############################

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
        

        if request.method == 'POST':
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

            # Fetch RSS feed and parse it using rss_to_json
            stories, raw_xml = fetch_rss_feed(url)
            parsed_data = rss_to_json(raw_xml)
            parsed_stories = parsed_data['stories']

            # Save feed and stories in the database
            new_feed = Feed(user_id=user.id, url=url, raw_xml=raw_xml)
            db.session.add(new_feed)
            db.session.flush()  # Ensure `new_feed.id` is available

            user_feed = UserFeed(user_id=user.id, feed_id=new_feed.id, is_following=True)
            db.session.add(user_feed)

            for story_data in parsed_stories:
                normalized_story = normalize_story_data(story_data)
                db.session.add(Story(feed_id=new_feed.id, data=normalized_story))

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

        # Fetch and parse RSS feed
        stories, raw_xml = fetch_rss_feed(url)
        parsed_data = rss_to_json(raw_xml)
        parsed_stories = parsed_data['stories']
        fields = list(parsed_stories[0].keys()) if parsed_stories else []

        return jsonify({
            'metadata': {
                'title': parsed_stories[0].get('title', 'No Title') if parsed_stories else 'No Title',
                'description': parsed_stories[0].get('description', 'No Description') if parsed_stories else 'No Description',
                'fields': fields,
            },
            'stories': parsed_stories[:10],  # Limit to the first 10 stories
            'raw_xml': raw_xml.decode('utf-8'),  # Include raw XML if needed
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



##############################
##  STORY MGMT
#############################

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
                normalized_story = normalize_story_data(story.data)
                stories_data.append({
                    'id': story.id,
                    'data': normalized_story,
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

            normalized_story = normalize_story_data(story_data)
            new_story = Story(feed_id=feed_id, data=normalized_story)
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




##########################################
####### RSS Handler Below
##########################################


def rss_to_json(raw_xml):
    """
    Convert RSS XML to JSON format, including unexpected data in a 'raw_metadata' field.
    """
    root = ET.fromstring(raw_xml)
    channel = root.find('channel')
    stories = []

    for item in channel.findall('item'):
        story = {
            'title': item.find('title').text if item.find('title') is not None else None,
            'link': item.find('link').text if item.find('link') is not None else None,
            'description': item.find('description').text if item.find('description') is not None else None,
            'published': item.find('pubDate').text if item.find('pubDate') is not None else None,
            'author': item.find('author').text if item.find('author') is not None else None,
            'categories': [category.text for category in item.findall('category')] if item.findall('category') else [],
            'custom_metadata': {}
        }

        # Capture unexpected tags
        raw_metadata = {}
        for child in item:
            tag = child.tag
            if tag not in ['title', 'link', 'description', 'pubDate', 'author', 'category', 'custom:metadata']:
                raw_metadata[tag] = child.text

        # Add raw_metadata if present
        if raw_metadata:
            story['custom_metadata']['raw_metadata'] = raw_metadata

        # Handle custom metadata
        if item.find('custom:metadata') is not None:
            story['custom_metadata'].update(json.loads(item.find('custom:metadata').text))

        stories.append(story)

    return {'stories': stories}



def json_to_rss(json_data, flatten_metadata=True):
    """
    Convert JSON format back to RSS XML, optionally flattening custom metadata fields.
    """
    root = ET.Element('rss', version="2.0")
    channel = ET.SubElement(root, 'channel')

    for story in json_data.get('stories', []):
        item = ET.SubElement(channel, 'item')

        # Add standard fields
        ET.SubElement(item, 'title').text = escape(story.get('title', 'No Title'))
        ET.SubElement(item, 'link').text = escape(story.get('link', '#'))
        ET.SubElement(item, 'description').text = sanitize_cdata(story.get('description', 'No Description'))
        if story.get('published'):
            ET.SubElement(item, 'pubDate').text = story['published']

        # Handle flattening of custom metadata
        custom_metadata = story.get('custom_metadata', {})
        raw_metadata = custom_metadata.get('raw_metadata', {})

        if flatten_metadata:
            # Promote raw metadata fields to top-level elements
            for tag, value in raw_metadata.items():
                if isinstance(value, list):
                    for item_value in value:
                        ET.SubElement(item, tag).text = escape(item_value)
                else:
                    ET.SubElement(item, tag).text = escape(value)
        else:
            # Embed raw metadata as a single element
            raw_metadata_element = ET.SubElement(item, 'custom:metadata')
            raw_metadata_element.text = sanitize_cdata(json.dumps(raw_metadata))

    return ET.tostring(root, encoding='utf-8', method='xml')



def sanitize_cdata(content):
    """
    Wraps content in CDATA if it contains special characters or HTML.
    """
    if "<" in content or ">" in content or "&" in content:
        return f"<![CDATA[{content}]]>"
    return content


def normalize_story_data(story):
    """
    Ensure consistency of story data during conversions.
    """
    return {
        'title': story.get('title', '').strip(),
        'link': story.get('link', '').strip(),
        'description': story.get('description', '').strip(),
        'published': story.get('published', '').strip(),
        'custom_metadata': story.get('custom_metadata', {})
    }



def generate_dynamic_rss(feed, stories):
    """
    Generate RSS feed, embedding additional metadata where necessary.
    """
    root = ET.Element('rss', version="2.0")
    channel = ET.SubElement(root, 'channel')

    # Add standard RSS metadata
    ET.SubElement(channel, 'title').text = escape(feed.url or "Untitled Feed")
    ET.SubElement(channel, 'link').text = escape(feed.url or "#")
    ET.SubElement(channel, 'description').text = "Generated RSS Feed with Custom Metadata"
    ET.SubElement(channel, 'language').text = "en-US"

    for story in stories:
        item = ET.SubElement(channel, 'item')

        # Add basic RSS fields
        ET.SubElement(item, 'title').text = escape(story.get('title', 'No Title'))
        ET.SubElement(item, 'link').text = escape(story.get('link', '#'))
        ET.SubElement(item, 'description').text = sanitize_cdata(story.get('description', 'No Description'))

        pub_date_raw = story.get('published', None)
        if pub_date_raw:
            ET.SubElement(item, 'pubDate').text = pub_date_raw
        else:
            ET.SubElement(item, 'pubDate').text = formatdate()

        # Additional fields
        if story.get('author'):
            ET.SubElement(item, 'author').text = escape(story['author'])
        if 'categories' in story:
            categories = story.get('categories', [])
            for category in categories:
                ET.SubElement(item, 'category').text = escape(category)

        # Embed additional JSON metadata
        custom_metadata = story.get('custom_metadata', {})
        raw_metadata = custom_metadata.get('raw_metadata', {})
        for tag, value in raw_metadata.items():
            if value is not None:  # Check for None values
                if isinstance(value, list):  # Handle lists
                    for sub_value in value:
                        ET.SubElement(item, tag).text = escape(sub_value)
                else:
                    ET.SubElement(item, tag).text = escape(value)

    return ET.tostring(root, encoding='utf-8', method='xml')



@app.route('/feeds/public/rss/<token>', methods=['GET'])
def get_public_rss_feed(token):
    """
    Fetch and return the RSS feed for a given public token.
    """
    try:
        print(f"[DEBUG] Token received: {token}")
        feed = Feed.query.filter_by(public_token=token).first()

        if not feed:
            print("[ERROR] Feed not found for the given token.")
            return jsonify({'error': 'Feed not found'}), 404
        
        # Ensure feed.stories is not None
        if not feed.stories:
            return jsonify({'error': 'No stories available for this feed'}), 404

        stories = [story.data for story in feed.stories]
        print(f"[DEBUG] Stories fetched: {stories}")

        # Generate RSS XML dynamically
        rss_xml = generate_dynamic_rss(feed, stories)
        return Response(rss_xml, mimetype='application/rss+xml')
    except Exception as e:
        print(f"[ERROR] Failed to fetch public RSS feed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/feeds/public/json/<token>', methods=['GET'])
def get_public_json_feed(token):
    """
    Fetch and return the JSON feed for a given public token.
    """
    try:
        feed = Feed.query.filter_by(public_token=token).first()

        if not feed:
            return jsonify({'error': 'Feed not found'}), 404

        stories = [story.data for story in feed.stories]

        # Return JSON response
        return jsonify({
            'feed': {
                'url': feed.url,
                'stories': stories,
                'raw_xml': feed.raw_xml
            }
        }), 200
    except Exception as e:
        print(f"[ERROR] Failed to fetch public JSON feed: {e}")
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