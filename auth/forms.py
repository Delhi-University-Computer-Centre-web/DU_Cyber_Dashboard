# auth/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=200)])
    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=50)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=4, max=200)])
    submit = SubmitField("Register")
