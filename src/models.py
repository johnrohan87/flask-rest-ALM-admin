import os
from hashlib import pbkdf2_hmac
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String, Boolean, Text, ForeignKey, Column
from sqlalchemy.orm import relationship, mapped_column, DeclarativeBase

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(Integer, primary_key=True)
    email = db.Column(String(120), unique=True, nullable=False)
    password = db.Column(String(80), unique=False, nullable=False)
    is_active = db.Column(Boolean(), unique=False, nullable=False)

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
    id = db.column(Integer, primary_key=True)
    email = db.column(String(120), unique=True, nullable=False)
    roles = db.column(Integer, unique=False, nullable=False)
    password = db.column(String(255), nullable=False)
    salt = db.column(String(255), nullable=False)
    text_files = relationship('TextFile', back_populates='person', lazy=True, cascade='all,delete')

    # tell python how to print the class object on the console
    def __repr__(self):
        '''return {
            "email": self.email,
            "roles": self.roles,
            "password": self.password,
            "salt": self.salt
        }'''
        return f"User(id={self.id!r}, email={self.email!r}, roles={self.roles!r})"

    # tell python how convert the class object into a dictionary ready to jsonify
    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "roles": self.roles
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
    id = db.column(Integer, primary_key=True)
    person_id = db.column(Integer, ForeignKey('person_account.id'))
    ip = db.column(String(20),unique=False, nullable=False)
    update_feed = db.column(Boolean, nullable=False)
    url = db.column(Text, nullable=False)
    text = db.column(Text, nullable=False)

    #person = relationship("Person", back_populates="textfile")

    # tell python how to print the class object on the console
    def __repr__(self):
        return f"TextFile(id={self.id!r}, person_id={self.person_id!r}, ip={self.ip!r})"

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