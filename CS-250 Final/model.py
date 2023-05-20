from app import db, UserMixin

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(40), nullable=False)
    name = db.Column(db.String(40), nullable=False)
    entries = db.relationship('Account', backref='user')


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    songName = db.Column(db.String(40))
    songFile = db.Column(db.String(100))
    coverArtFile = db.Column(db.String(100))
    jsonObject = db.Column(db.String(800))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))