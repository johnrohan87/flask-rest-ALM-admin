#!/usr/bin/env python3
"""
Test script to check database relationships and data display issues.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from models import db, User, Feed, Story, UserFeed, UserStory
from main import app

def test_data_relationships():
    with app.app_context():
        print("=== DATABASE RELATIONSHIP TESTS ===\n")
        
        # Test Users
        users = User.query.all()
        print(f"Total Users: {len(users)}")
        for user in users[:3]:  # Show first 3
            print(f"  - User {user.id}: {user.email} ({user.username})")
        print()
        
        # Test Feeds
        feeds = Feed.query.all()
        print(f"Total Feeds: {len(feeds)}")
        for feed in feeds[:3]:  # Show first 3
            print(f"  - Feed {feed.id}: {feed.url[:50]}...")
            print(f"    Owner: User {feed.user_id}")
            print(f"    Stories: {len(feed.stories)}")
            print(f"    Subscribers: {len(feed.user_feeds)}")
        print()
        
        # Test Stories
        stories = Story.query.all()
        print(f"Total Stories: {len(stories)}")
        for story in stories[:3]:  # Show first 3
            title = story.data.get('title', 'No Title') if story.data else 'No Data'
            print(f"  - Story {story.id}: {title[:50]}...")
            print(f"    Feed: {story.feed_id}")
            print(f"    User interactions: {len(story.user_stories)}")
        print()
        
        # Test UserFeeds
        user_feeds = UserFeed.query.all()
        print(f"Total UserFeed relationships: {len(user_feeds)}")
        for uf in user_feeds[:3]:  # Show first 3
            print(f"  - UserFeed {uf.id}: User {uf.user_id} -> Feed {uf.feed_id}")
            print(f"    Following: {uf.is_following}, Save all: {uf.save_all_new_stories}")
        print()
        
        # Test UserStories
        user_stories = UserStory.query.all()
        print(f"Total UserStory relationships: {len(user_stories)}")
        for us in user_stories[:3]:  # Show first 3
            print(f"  - UserStory {us.id}: User {us.user_id} -> Story {us.story_id}")
            print(f"    Saved: {us.is_saved}, Watched: {us.is_watched}")
        print()
        
        # Test relationship integrity
        print("=== RELATIONSHIP INTEGRITY CHECKS ===\n")
        
        # Check for orphaned records
        orphaned_stories = Story.query.filter(~Story.feed_id.in_(
            db.session.query(Feed.id)
        )).all()
        print(f"Orphaned Stories (no feed): {len(orphaned_stories)}")
        
        orphaned_user_feeds = UserFeed.query.filter(~UserFeed.user_id.in_(
            db.session.query(User.id)
        )).all()
        print(f"Orphaned UserFeeds (no user): {len(orphaned_user_feeds)}")
        
        orphaned_user_stories = UserStory.query.filter(~UserStory.user_id.in_(
            db.session.query(User.id)
        )).all()
        print(f"Orphaned UserStories (no user): {len(orphaned_user_stories)}")
        
        # Test JSON data integrity
        stories_with_bad_data = Story.query.filter(Story.data.is_(None)).all()
        print(f"Stories with NULL data: {len(stories_with_bad_data)}")
        
        stories_with_empty_data = [s for s in Story.query.all() if not s.data]
        print(f"Stories with empty data: {len(stories_with_empty_data)}")
        
        print("\n=== SUMMARY ===")
        print("If numbers look good and no orphaned records, relationships are healthy!")

if __name__ == "__main__":
    test_data_relationships()