import os
from hashlib import pbkdf2_hmac
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Boolean, Text, ForeignKey, Column, Table
from sqlalchemy.orm import relationship, DeclarativeBase, backref

db = SQLAlchemy()

#association_table = Table(
#    "association",
#    db.Model.metadata,
#    Column("textfile_table_id", Integer, ForeignKey("textfile_table.id"), primary_key=True),
#    Column("feedpost_table_id", Integer, ForeignKey("feedpost_table.id"), primary_key=True),
#)

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), unique=False, nullable=False)
    is_active = db.Column(db.Boolean(), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            # do not serialize the password, its a security breach
        }

class Person(db.Model):
    __tablename__ = "person_account"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    roles = db.Column(db.Integer, unique=False, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    is_fresh = db.Column(db.Boolean, nullable=False)
    text_files = relationship('TextFile', back_populates='person', cascade='all,delete')

    # tell python how to print the class object on the console
    def __repr__(self):
        '''return {
            "email": self.email,
            "roles": self.roles,
            "password": self.password,
            "salt": self.salt
        }'''
        #return f"<User id={self.id!r}, email={self.email!r}, roles={self.roles!r}, is_fresh={self.is_fresh!r} >"
        return '<Person Email %r>' % self.email
    def __str__(self):
        return str(self.id)
    # tell python how convert the class object into a dictionary ready to jsonify
    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "roles": self.roles,
            "is_fresh": self.is_fresh
        }
            #***Testing only***
            #"password": self.password,
            #"salt": self.salt

    # NOTE: In a real application make sure to properly hash and salt passwords
    def check_password(self, password):
        #return compare_digest(password, "password")
        return password == self.password

    def generate_salt():
        salt = os.urandom(16)
        return salt.hex()

    def generate_hash(plain_password, password_salt):
        password_hash = pbkdf2_hmac(
            "sha256",
            b"%b" % bytes(plain_password, "utf-8"),
            b"%b" % bytes(password_salt, "utf-8"),
            10000,
        )
        return password_hash.hex()

class TextFile(db.Model):
    __tablename__ = "textfile_table"
    #form_columns = ('id', 'person_id', 'ip', 'update_feed', 'url', 'text', 'person', 'feeds')
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, ForeignKey('person_account.id'), nullable=False)
    ip = db.Column(db.String(20),unique=False, nullable=False)
    update_feed = db.Column(db.Boolean, nullable=False)
    url = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)
    person = relationship('Person', back_populates='text_files')
    feeds = relationship('FeedPost', back_populates='feed', collection_class=set, lazy=True, cascade='all,delete')


    # tell python how to print the class object on the console
    def __repr__(self):
        #return f"<TextFile id={self.id!r}, person_id={self.person_id!r}, ip={self.ip!r} >"
        return '<TextFile Person_id %r>' % self.person_id
    def __str__(self):
        f'{self.person_id} {self.feeds}'
    # tell python how convert the class object into a dictionary ready to jsonify
    def serialize(self):
        return {
            "file id": self.id,
            "person id": self.person_id,
            "ip": self.ip,
            "update feed": self.update_feed,
            "url": self.url,
            "file text": self.text
        }
    
class FeedPost(db.Model):
    __tablename__ = "feedpost_table"
    #form_columns = ('id', 'feed_id', 'title', 'link', 'published', 'author', 'summary', 'tags', 'feed')
    id = db.Column(db.Integer, primary_key=True)
    feed_id = db.Column(db.Integer, ForeignKey('textfile_table.id'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    link = db.Column(db.Text, nullable=False)
    published = db.Column(db.Text, nullable=False) # Unicode string
    published_parsed = db.Column(db.Text, nullable=False) # Time object
    author = db.Column(db.Text, nullable=False)
    summary = db.Column(db.Text, nullable=False)
    tags = db.Column(db.Text, nullable=False)

    feed = relationship('TextFile', back_populates='feeds', lazy=True)

    def __repr__(self):
        #return f"<FeedPost(id={self.id!r}, feed_id={self.feed_id!r}, title={self.title!r})>"
        return f'<FeedPost FeedID:{self.id}, Title:{self.title}>'  
    def __str__(self):
        f'feed_id {self.feed_id} feed {self.feed} '

    def serialize(self):
        return {
            "id": self.id,
            "feed_id": self.feed_id,
            "title": self.title,
            "link": self.link,
            "published": self.published,
            "published_parsed": self.published_parsed,
            "author": self.author,
            "summary": self.summary,
            "tags": self.tags,
        }
    
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    userID = db.Column(db.Integer, nullable=False)
    permissions = db.Column(db.String(50), nullable=False, default='guest')

    def serialize(self):
        return {
            "id": self.id,
            "text": self.text,
            "userID": self.userID,
            "permissions": self.permissions,
        }