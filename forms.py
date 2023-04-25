
from email.policy import default
from lib2to3.pgen2.token import EQUAL
from tokenize import String
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, DateField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from wtforms.widgets import TextArea

class LoginForm(FlaskForm):
    email = StringField("Электронная почта: ", validators=[Email("Некорректный адрес электронной почты")])
    psw = PasswordField("Пароль: ", validators=[DataRequired(), Length(min=4, max=100, message="Пароль от 4 до 100")])
    remember = BooleanField("Запомнить", default=False)
    submit = SubmitField("Войти")
    
    
class RegisterForm(FlaskForm):
    username = StringField("Имя: ", validators=[Length(min=4, max=30, message="Имя от 4 до 30")])
    email = StringField("Email: ", validators=[Email("Неккоректный email")])
    psw = PasswordField("Пароль: ", validators=[DataRequired(), Length(min=4, max=100, message="Пароль от 4 до 100 символов")])
    psw2 = PasswordField("Повтор пароля: ", validators=[DataRequired(), EqualTo('psw', message="Пароли не совпадают")])
    submit = SubmitField("Регистрация")
    
    
class ProfileDetailsForm(FlaskForm):
    get_email_from_group = BooleanField('Получать электронные письма о новостях и обновлениях', default=False)
    get_ping_from_group = BooleanField('Уведомление о начале нового обсуждения в Вашей группе.', default=False)
    date_of_birth = DateField(format='%Y-%m-%d')
    show_date_of_birth = BooleanField('Показывать год рождения', default=False)
    adress = StringField('Адрес:')
    sex = RadioField('Пол:', choices=[('man','Мужской'),('woman','Женский'),('other','Другое')])
    about_me = StringField(validators=[Length(min=20, max=300, message="Текст от 20 до 300 символов")], widget=TextArea())
    submit = SubmitField("Сохранить")
    
    
class ProfileSecurity(FlaskForm):
    psw_now = PasswordField('Ваш текущий пароль', validators=[DataRequired(), Length(min=4, max=100, message="Пароль может быть только от 4 до 100 символов")])
    psw_new = StringField('Новый пароль', validators=[DataRequired(), Length(min=4, max=100, message="Пароль от 4 до 100 символов")])
    psw_confirm = StringField('Подтверждение нового пароля', validators=[DataRequired(), Length(min=4, max=100, message="Пароль от 4 до 100 символов")])
    submit = SubmitField("Сохранить")


class PostAdd(FlaskForm):
    threads_name = StringField('', validators=[DataRequired(), Length(min=4, max=100, message="Название от 4 до 100 символов")])
    threads_text = StringField('', validators=[DataRequired(), Length(min=20, max=500, message="Текст от 20 до 500 символов")], widget=TextArea())
    submit = SubmitField('Создать тему')
    
    
class ReplyToThread(FlaskForm):
    reply = StringField('', validators=[DataRequired(), Length(min=10, max=300, message="Название от 10 до 300 символов")], widget=TextArea())
    submit = SubmitField('Ответить')