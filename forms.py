
from email.policy import default
from lib2to3.pgen2.token import EQUAL
from tokenize import String
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField, DateField, RadioField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from wtforms.widgets import TextArea

class LoginForm(FlaskForm):
    email = StringField("Email: ", validators=[Email("Incorrect email address")])
    psw = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=100, message="Password from 4 to 100")])
    remember = BooleanField("Remember", default=False)
    submit = SubmitField("Login")
    
    
class RegisterForm(FlaskForm):
    username = StringField("Name: ", validators=[Length(min=4, max=30, message="Name from 4 to 30")])
    email = StringField("Email: ", validators=[Email("Incorrect email address")])
    psw = PasswordField("Password: ", validators=[DataRequired(), Length(min=4, max=100, message="Password from 4 to 100")])
    psw2 = PasswordField("Password repeat: ", validators=[DataRequired(), EqualTo('psw', message="Password mismatch")])
    submit = SubmitField("Registration")
    
    
class ProfileDetailsForm(FlaskForm):
    get_email_from_group = BooleanField('Receive emails about news and updates', default=False)
    get_ping_from_group = BooleanField('Notification about the start of a new discussion in your group.', default=False)
    date_of_birth = DateField(format='%Y-%m-%d')
    show_date_of_birth = BooleanField('Show year of birth', default=False)
    adress = StringField('Address:')
    sex = RadioField('Gender:', choices=[('man','Male'),('woman','Female'),('other','Other')])
    about_me = StringField(validators=[Length(min=20, max=300, message="Text from 20 to 300 characters")], widget=TextArea())
    submit = SubmitField("Save")
    
    
class ProfileSecurity(FlaskForm):
    psw_now = PasswordField('Your current password', validators=[DataRequired(), Length(min=4, max=100, message="Password can only be between 4 and 100 characters")])
    psw_new = StringField('New Password', validators=[DataRequired(), Length(min=4, max=100, message="Password from 4 to 100 characters")])
    psw_confirm = StringField('New password confirmation', validators=[DataRequired(), Length(min=4, max=100, message="Password from 4 to 100 characters")])
    submit = SubmitField("Save")


class PostAdd(FlaskForm):
    threads_name = StringField('', validators=[DataRequired(), Length(min=4, max=100, message="Title from 4 to 100 characters")])
    threads_text = StringField('', validators=[DataRequired(), Length(min=20, max=500, message="Text from 20 to 500 characters")], widget=TextArea())
    submit = SubmitField('Create topic')
    
    
class ReplyToThread(FlaskForm):
    reply = StringField('', validators=[DataRequired(), Length(min=10, max=300, message="Title from 10 to 300 characters")], widget=TextArea())
    submit = SubmitField('Answer')