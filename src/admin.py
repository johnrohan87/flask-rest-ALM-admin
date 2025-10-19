import os
from flask_admin import Admin
from models import db, User, Person, TextFile, FeedPost, Todo, Feed, Story, UserFeed, UserStory
from flask_admin.contrib.sqla import ModelView
from markupsafe import Markup

def setup_admin(app):
    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    #app.run(debug=True)
    admin = Admin(app, name='4Geeks Admin', template_mode='bootstrap3')

    class TextFileMV(ModelView):
        column_display_pk = True 
        column_hide_backrefs = False
        column_display_all_relations = True
        #ignore_hidden = False
        #create_modal = True
        #edit_modal = True
        form_columns = ['person_id', 'ip', 'update_feed', 'url', 'text']
        column_list = ['id', 'person_id', 'person', 'feeds', 'ip', 'update_feed', 'url', 'text']

    class LegacyFeedPostMV(ModelView):
        #column_display_pk = True 
        #column_hide_backrefs = False
        #column_display_all_relations = True
        form_columns = ['feed_id', 'title', 'link', 'published', 'published_parsed', 'author', 'summary', 'tags']
        column_list = ['id', 'feed_id', 'title', 'link', 'published', 'published_parsed', 'author', 'summary', 'tags']

    class ToDoMV(ModelView):
            #column_display_pk = True 
            #column_hide_backrefs = False
            #column_display_all_relations = True
            form_columns = ['id', 'text', 'userID', 'permissions']
            column_list = ['id', 'text', 'userID', 'permissions']

    class UserMV(ModelView):
        column_display_pk = True
        form_columns = ['auth0_id', 'email', 'username', 'is_active']
        column_list = ['id', 'email', 'auth0_id', 'username', 'is_active', 'created_at']
        column_searchable_list = ['email', 'username', 'auth0_id']
        column_filters = ['is_active', 'created_at']
        
    class FeedMV(ModelView):
        column_display_pk = True
        form_columns = ['user_id', 'url', 'public_token']
        column_list = ['id', 'user', 'url', 'public_token', 'created_at', 'updated_at']
        column_searchable_list = ['url']
        column_filters = ['created_at', 'user_id']
        
    class StoryMV(ModelView):
        column_display_pk = True
        form_columns = ['feed_id', 'custom_title', 'custom_content']
        column_list = ['id', 'feed', 'story_title', 'story_link', 'created_at']
        column_filters = ['created_at', 'feed_id']
        column_searchable_list = ['custom_title', 'custom_content']
        
        def _story_title_formatter(view, context, model, name):
            if model.data and isinstance(model.data, dict):
                title = model.data.get('title', model.custom_title or 'No Title')
                return Markup(f'<span title="{title}">{title[:60]}...</span>' if len(title) > 60 else title)
            return model.custom_title or 'No Data'
            
        def _story_link_formatter(view, context, model, name):
            if model.data and isinstance(model.data, dict):
                link = model.data.get('link', 'No Link')
                if link and link != 'No Link':
                    return Markup(f'<a href="{link}" target="_blank" title="{link}">{link[:40]}...</a>' if len(link) > 40 else f'<a href="{link}" target="_blank">{link}</a>')
            return 'No Link'
            
        column_formatters = {
            'story_title': _story_title_formatter,
            'story_link': _story_link_formatter
        }
        
    class UserFeedMV(ModelView):
        column_display_pk = True
        form_columns = ['user_id', 'feed_id', 'is_following', 'save_all_new_stories']
        column_list = ['id', 'user', 'feed', 'is_following', 'save_all_new_stories', 'created_at']
        column_filters = ['is_following', 'save_all_new_stories', 'created_at']
        
    class UserStoryMV(ModelView):
        column_display_pk = True
        form_columns = ['user_id', 'story_id', 'is_saved', 'is_watched']
        column_list = ['id', 'user', 'story', 'is_saved', 'is_watched', 'created_at']
        column_filters = ['is_saved', 'is_watched', 'created_at']

    
    # Core RSS Management Models (Current System)
    admin.add_view(UserMV(User, db.session))
    admin.add_view(FeedMV(Feed, db.session))
    admin.add_view(StoryMV(Story, db.session))
    admin.add_view(UserFeedMV(UserFeed, db.session))
    admin.add_view(UserStoryMV(UserStory, db.session))
    
    # Legacy Models (Previous System)
    admin.add_view(ModelView(Person, db.session))
    admin.add_view(ToDoMV(Todo, db.session))
    admin.add_view(TextFileMV(TextFile, db.session))
    admin.add_view(LegacyFeedPostMV(FeedPost, db.session))

    # You can duplicate that line to add mew models
    # admin.add_view(ModelView(YourModelName, db.session))