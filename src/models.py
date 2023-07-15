import os
from hashlib import pbkdf2_hmac
from flask_sqlalchemy import SQLAlchemy, Integer, String, Boolean, Text
from sqlalchemy.orm import relationship, mapped_column, DeclarativeBase

db = SQLAlchemy()

class Base(DeclarativeBase):
    pass

class User(db.Model):
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

class Person(Base):
    __tablename__ = "person_account"
    id = mapped_column(Integer, primary_key=True)
    email = mapped_column(String(120), unique=True, nullable=False)
    roles = mapped_column(Integer, unique=False, nullable=False)
    password = mapped_column(String(255), nullable=False)
    salt = mapped_column(String(255), nullable=False)
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

class TextFile(Base):
    __tablename__ = "textfile"
    id = mapped_column('textfile_id', Integer, primary_key=True)
    person_id = mapped_column('owner_id', Integer, ForeignKey('person_account.id'))
    ip = mapped_column(String(20),unique=False, nullable=False)
    update_feed = mapped_column(Boolean, nullable=False)
    url = mapped_column(Text, nullable=False)
    text = mapped_column(Text, nullable=False)

    person = relationship("Person", back_populates="textfile")

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