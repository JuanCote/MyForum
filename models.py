from ast import excepthandler
from email.policy import default
from enum import unique

from flask_login import UserMixin
from werkzeug.security import check_password_hash

from flask import url_for
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def verify_ext(filename):
    ext = filename.split('.')[-1]
    if ext in ('png', 'PNG', 'jpg'):
        return True
    return False


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(500))
    get_email_from_group = db.Column(db.Boolean, nullable=True, default=False)
    get_ping_from_group = db.Column(db.Boolean, default=False)
    date_of_birth = db.Column(db.Date)
    show_date_of_birth = db.Column(db.Boolean, default=False)
    adress = db.Column(db.String(300))
    sex = db.Column(db.String(10))
    about_me = db.Column(db.Text(400))
    avatar = db.Column(db.BLOB)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<users{self.id}>'


def get_avatar(id):
    from main import app
    img = None
    user = User.query.filter_by(id=id).first()
    if user.avatar is None:
        try:
            with app.open_resource(app.root_path + url_for('static', filename='images/pngwing.com.png'), "rb") as f:
                img = f.read()
        except:
            print('Не найден аватар по умолчанию')
    else:
        img = user.avatar
    return img


class Sections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    section_name = db.Column(db.String(50), nullable=True, )


class Threads(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    threads_name = db.Column(db.String(200), nullable=True)
    parent_id = db.Column(db.Integer)
    section = db.Column(db.Integer)


class Under_threads(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    threads_name = db.Column(db.String(400), nullable=True)
    threads_text = db.Column(db.String(1500), nullable=True)
    parent_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    username = db.Column(db.String(100))
    time = db.Column(db.Date)


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text)
    user_id = db.Column(db.Integer)
    parent_id = db.Column(db.Integer)
    time = db.Column(db.Date)