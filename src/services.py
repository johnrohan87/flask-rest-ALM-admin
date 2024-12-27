import feedparser
import requests

def fetch_rss_feed(url):
    try:
        # Fetch the raw feed content
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch RSS feed: {response.status_code}")

        # Parse the feed content
        feed = feedparser.parse(response.content)
        if feed.bozo:  # Check for parsing errors
            raise Exception(f"Error parsing feed: {feed.bozo_exception}")

        # Extract stories
        stories = []
        for entry in feed.entries:
            story_data = {key: entry.get(key) for key in entry.keys()}
            stories.append(story_data)

        # Return stories and raw XML for debugging or storage
        return stories, response.content

    except requests.exceptions.RequestException as e:
        raise Exception(f"HTTP request failed: {e}")
    except Exception as e:
        raise Exception(f"Error processing feed: {e}")
