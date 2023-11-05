import os
from flask_admin import Admin
from models import db, User, Person, TextFile, FeedPost
from flask_admin.contrib.sqla import ModelView

def setup_admin(app):
    app.secret_key = os.environ.get('FLASK_APP_KEY', 'sample key')
    app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
    admin = Admin(app, name='4Geeks Admin', template_mode='bootstrap3')

    class TextFileMV(ModelView):
        column_display_pk = True 
        column_hide_backrefs = False
        #create_modal = True
        #edit_modal = True
        #column_searchable_list = ['person_id']
        #form_columns = ('id', 'ip', 'update_feed', 'url', 'text')
        #column_editable_list = ('id', 'ip', 'update_feed', 'url', 'text')
        inline_models = (Person, )

    
    # Add your models here, for example this is how we add a the User model to the admin
    admin.add_view(ModelView(User, db.session))
    admin.add_view(ModelView(Person, db.session))
    admin.add_view(TextFileMV(TextFile, db.session))
    admin.add_view(ModelView(FeedPost, db.session))

    # You can duplicate that line to add mew models
    # admin.add_view(ModelView(YourModelName, db.session))