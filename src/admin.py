import os
from flask_admin import Admin
from models import db, User, Person, TextFile, FeedPost
from flask_admin.contrib.sqla import ModelView

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
        column_list = ('id', 'person_id', 'person', 'feeds', 'ip', 'update_feed', 'url', 'text')

    class FeedMV(ModelView):
        column_display_pk = True 
        column_hide_backrefs = False
        column_display_all_relations = True
        #form_columns = ['person_id', 'ip', 'update_feed', 'url', 'text']
        column_list = ('id', 'feed_id', 'title', 'link', 'published', 'published_parsed', 'author', 'summary', 'tags')

    
    # Add your models here, for example this is how we add a the User model to the admin
    admin.add_view(ModelView(User, db.session))
    admin.add_view(ModelView(Person, db.session))
    admin.add_view(TextFileMV(TextFile, db.session))
    admin.add_view(ModelView(FeedMV, db.session))

    # You can duplicate that line to add mew models
    # admin.add_view(ModelView(YourModelName, db.session))