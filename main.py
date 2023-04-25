from flask import Flask
from flask_migrate import Migrate

from config import Config
from models import db

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
NAME = 'main'
from flask import Flask, make_response, render_template, url_for, request, redirect, flash
from datetime import datetime
import sqlite3
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from flask_migrate import Migrate

from config import Config
from forms import LoginForm, RegisterForm, ProfileDetailsForm, ProfileSecurity, PostAdd, ReplyToThread
from models import db, Sections, User, getAvatar, verifyExt, Under_threads, Messages, Threads

DEBUG = True
MAX_CONTENT_LENGTH = 1024 * 1024  # TODO: Изменить дерьмо

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

app = Flask(__name__, template_folder='templates')
app.config.from_object(Config)
metadata = MetaData(naming_convention=convention)
db.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)
login = LoginManager(app)



@login.user_loader
def load_user(id):
    return User.query.get(int(id))


mus = ['letgo', 'asdas', 'asdasd']


@app.route('/')
def index():
    sections = Sections.query.all()
    threads_dict = dict()
    for section in sections:
        threads = Threads.query.filter_by(section=section.id).all()
        threads_dict[section.section_name] = {}
        for thread in threads:
            threads_dict[section.section_name][thread.threads_name] = {
                'id': thread.id,
                'translate_name': thread.threads_name.replace(' ', '-').lower() + '.' + str(thread.id)
            }
    return render_template('index.html', content=threads_dict)


@app.route('/forums/<thread_name>/')
def forums(thread_name):
    id = thread_name.split('.')[-1]
    parent = threads.query.filter_by(id=id).first()
    parent_name = parent.threads_name
    threads = threads.query.filter_by(parent_id=parent.id).all()
    threads_dict = dict()
    for thread in threads:
        threads_dict[thread.threads_name] = {
            'id': thread.id,
            'translate_name': thread.threads_name.replace(' ', '-').lower() + '.' + str(thread.id)
        }

    User, Thread = User, under_threads
    # Join user and under_thread
    under_threads = db.session.query(User, Thread).filter(Thread.parent_id == id).join(Thread,
                                                                                       User.id == Thread.user_id).all()
    under_threads_dict = dict()

    for under_thread in under_threads:
        under_threads_dict[under_thread[1].threads_name] = {
            'id': under_thread[1].id,
            'translate_name': under_thread[1].threads_name.replace(' ', '-').lower() + '.' + str(under_thread[1].id),
            'username': under_thread[1].username,
            'user_ava': under_thread[0].avatar,
            'user_id': under_thread[0].id,
            'time': under_thread[1].time
        }
    if threads_dict == {}:
        threads_dict = None
    if under_threads_dict == {}:
        under_threads_dict = None
    return render_template('forums.html', thread_name=thread_name, name=parent_name, content=threads_dict,
                           content2=under_threads_dict)


@app.route('/forums/<thread_name>/post-add', methods=["POST", "GET"])
@login_required
def add_post(thread_name):
    form = PostAdd()
    id = thread_name.split('.')[-1]

    if form.validate_on_submit():
        print('submit')
        threads_name = form.threads_name.data
        thread_text = form.threads_text.data
        thread_time = datetime.utcnow()
        parent_id = id
        user_id = current_user.id
        username = User.query.filter_by(id=user_id).first().username

        try:
            thread = under_threads(threads_name=threads_name, threads_text=thread_text, time=thread_time,
                                          parent_id=parent_id, user_id=user_id, username=username)
            db.session.add(thread)
            db.session.commit()

            return redirect(url_for('forums', thread_name=thread_name))
        except:
            print('Error db')

    return render_template('add-post.html', thread_name=thread_name, form=form)


@app.route('/thread/<underthread_name>/relpy_to_thread', methods=["POST", "GET"])
def reply_to_thread(underthread_name):
    form = ReplyToThread()

    if form.validate_on_submit() and request.method == 'POST':
        message = form.reply.data
        time = datetime.utcnow()
        user_id = current_user.id
        parent_id = underthread_name.split('.')[-1]

        try:
            message = Messages(message=message, time=time, user_id=user_id, parent_id=parent_id)
            db.session.add(message)
            db.session.commit()
            return redirect(url_for('thread', underthread_name=underthread_name))
        except:
            print('DB error')

    return render_template('reply-to-thread.html', form=form, underthread_name=underthread_name)


@app.route('/thread/<underthread_name>/')
def thread(underthread_name):
    id = underthread_name.split('.')[-1]
    parent = Under_threads.query.filter_by(id=id).first()
    parent_name = parent.threads_name

    messages = Messages.query.filter_by(parent_id=id).all()
    messages_dict = dict()

    first_message = Under_threads.query.filter_by(id=id).first()
    username = username = User.query.filter_by(id=first_message.user_id).first()
    messages_dict['first_message'] = {
        'user_id': first_message.user_id,
        'username': username.username,
        'date': first_message.time,
        'message': first_message.threads_text,
        'ava': username.avatar
    }

    for message in messages:
        username = User.query.filter_by(id=message.user_id).first()
        messages_dict[message.id] = {
            'user_id': username.id,
            'username': username.username,
            'date': datetime.strptime(str(message.time), '%Y-%m-%d').strftime('%m.%d.%Y'),
            'message': message.message,
            'ava': username.avatar
        }
    return render_template('thread.html', name=parent_name, content=messages_dict, underthread_name=underthread_name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.psw.data):
            flash('Неверный адрес электронной почты или пароль', 'flash-login')
            return (redirect(request.args.get("next") or url_for('login')))
        login_user(user, remember=form.remember.data)
        return redirect(url_for('index'))
    return render_template('login.html', title="Авторизация", form=form)


@app.route('/register', methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        if not User.query.filter(User.email == form.email.data).all():
            if not User.query.filter_by(username=form.username.data).first():
                hash = generate_password_hash(form.psw.data)
                u = User(email=form.email.data, password_hash=hash, username=form.username.data)
                db.session.add(u)
                db.session.commit()
                flash('Вы успешно зарегестрировались', 'flash-register-success')
                return redirect(url_for('login'))
            else:
                flash('Этот ник уже занят', 'flask-register-error')
        else:
            flash('Эта почта уже занята', 'flash-register-error')
    return render_template('register.html', form=form)


@app.route('/profile/account-details', methods=["POST", "GET"])
@login_required
def profile():
    user = User.query.filter_by(id=current_user.get_id()).first()
    form = ProfileDetailsForm()
    if request.method == 'POST':
        if request.form.get('action1') == 'Загрузить':
            file = request.files['file']
            if verifyExt(file.filename):
                img = file.read()
                binary = sqlite3.Binary(img)
                user.avatar = binary
                local_object = db.session.merge(user)
                try:
                    flash('Аватар успешно обновлен', 'ava_success')
                except:

                    flash('Ошибка при добавлении файла в базу', 'ava_error')
            elif not file:
                pass
            else:
                flash("Неверный формат файла", 'ava_error')
            user.get_email_from_group = form.get_email_from_group.data
            user.get_ping_from_group = form.get_ping_from_group.data
            user.date_of_birth = form.date_of_birth.data
            user.show_date_of_birth = form.show_date_of_birth.data
            user.adress = form.adress.data
            user.sex = form.sex.data
            user.about_me = form.about_me.data
            local_object = db.session.merge(user)
            try:
                db.session.add(local_object)
                db.session.commit()
                flash('Профиль успешно изменен', 'success_profile')
            except:
                flash('Ошибка при добавлениив базу данных', 'error_profile')
    form.adress.data = user.adress
    form.about_me.data = user.about_me
    sex_pocket = {'man': False,
                  'woman': False,
                  'other': False}
    if user.sex == 'man':
        sex_pocket['man'] = 'checked'
    elif user.sex == 'woman':
        sex_pocket['woman'] = 'checked'
    else:
        sex_pocket['other'] = 'checked'
    return render_template('profile-account-details.html', form=form, user=user, sex_pocket=sex_pocket)


@app.route('/profile/security', methods=["POST", "GET"])
@login_required
def security():
    user = User.query.filter_by(id=current_user.get_id()).first()
    form = ProfileSecurity()
    new = form.psw_new.data
    if request.method == 'POST' and form.validate():
        if form.psw_new.data != form.psw_confirm.data:
            flash('Пароли не совпадают', 'flash-security-error')
        else:
            if user is None or not user.check_password(form.psw_now.data):
                flash('Неверный текущий пароль', 'flash-security-error')
            else:
                if form.psw_now.data == form.psw_new.data:
                    flash('Новый пароль не может совпадать со старым', 'flash-security-error-1')
                else:
                    user.password_hash = generate_password_hash(form.psw_new.data)
                    local = db.session.merge(user)
                    try:
                        db.session.add(local)
                        db.session.commit()
                        flash('Пароль успешно изменен', 'flash-security-success')
                    except:
                        flash('Ошибка при добавлении в базу данных', 'flash-security-error')
                        print('Ошибка при добавлении в базу данных')
    else:
        print('not enter')
    return render_template('profile-security.html', form=form)


@app.route('/userava')
@login_required
def userava():
    img = getAvatar(current_user.get_id())
    h = make_response(img)
    h.headers['Content-Type'] = 'image/png'
    return h


@app.route('/userava_thread/<id>')
def userava_thread(id):
    img = getAvatar(id)
    h = make_response(img)
    h.headers['Content-Type'] = 'image/png'
    return h


if __name__ == "__main__":
    app.run(debug=DEBUG, use_reloader=False)
