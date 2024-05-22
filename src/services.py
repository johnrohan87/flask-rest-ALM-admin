import feedparser

def fetch_rss_feed(url):
    feed = feedparser.parse(url)
    raw_xml = feed['feed']
    stories = []
    for entry in feed.entries:
        story_data = {key: entry.get(key) for key in entry.keys()}
        stories.append(story_data)
    return stories, raw_xml