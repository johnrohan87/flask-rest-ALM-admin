import os
from hashlib import pbkdf2_hmac
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify, dumps

db = SQLAlchemy()

class User(db.Model):
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
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    roles = db.Column(db.Integer, unique=False, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    text_files = db.relationship('TextFile', backref='person', lazy=True, cascade='all,delete')

    # tell python how to print the class object on the console
    def __repr__(self):
        return {
            "email": self.email,
            "roles": self.roles,
            "password": self.password,
            "salt": self.salt,
            "text_files": [ item.serialize() for item in self.text_files ]
        }

    # tell python how convert the class object into a dictionary ready to jsonify
    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "roles": self.roles,
            "text_files": [ item.serialize() for item in self.text_files ]
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
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), nullable=False)
    ip = db.Column(db.String(20),unique=False, nullable=False)
    update_feed = db.Column(db.Boolean, nullable=False)
    url = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)


    # tell python how to print the class object on the console
    def __repr__(self):
        return {
            "file id": self.id,
            "person id": self.person_id,
            "ip": self.ip,
            "update feed": self.update_feed,
            "url": self.url,
            "file text": self.text
        }

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