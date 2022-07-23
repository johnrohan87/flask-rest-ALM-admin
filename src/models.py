from flask_sqlalchemy import SQLAlchemy

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
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_salt = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # tell python how to print the class object on the console
    def __repr__(self):
        return '<Person %r>' % self.username

    # tell python how convert the class object into a dictionary ready to jsonify
    def serialize(self):
        return {
            "username": self.username,
            "email": self.email
        }