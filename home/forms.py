from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, SubmitField, FileField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email, Regexp
from app.models import User
from sqlalchemy import or_


class RegistForm(FlaskForm):
    name = StringField(
        label='昵称',
        validators=[
            DataRequired("请输入昵称！")
        ],
        description="昵称",
        render_kw={
            'class': "form-control input-lg",
            'placeholder': "请输入昵称！",
            'autofocus': 'autofocus'
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码!")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码",
        }
    )
    repwd = PasswordField(
        label="重复密码",
        validators=[
            DataRequired("请输入重复密码!"),
            EqualTo("pwd", message="两次密码不一致！")
        ],
        description="重复密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入重复密码",
        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            'class': "form-control input-lg",
            'placeholder': "请输入邮箱！",
        }
    )
    phone = StringField(
        label='电话',
        validators=[
            DataRequired("请输入电话！"),
            Regexp("1[3458]\\d{9}", message="无效手机号码！")
        ],
        description="电话",
        render_kw={
            'class': "form-control input-lg",
            'placeholder': "请输入电话！",
        }
    )
    submit = SubmitField(
        label="注册",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user:
            raise ValidationError("昵称已经存在，请重新输入！")

    def validate_email(self, field):
        email = field.data
        user = User.query.filter_by(email=email).count()
        if user:
            raise ValidationError("邮箱已经存在，请重新输入！")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.filter_by(phone=phone).count()
        if user:
            raise ValidationError("电话号码已经存在，请重新输入！")


class LoginForm(FlaskForm):
    account = StringField(
        label='账号',
        validators=[
            DataRequired("请输入昵称,邮箱,电话号码！")
        ],
        description="账号",
        render_kw={
            'class': "form-control input-lg",
            'placeholder': "请输入账号！",
            'autofocus': 'autofocus'
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码!")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码",
        }
    )
    submit = SubmitField(
        label="登陆",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    def validate_account(self, field):
        name = field.data
        user = User.query.filter(or_(User.name == name, User.email == name, User.phone == name)).count()
        if user == 0:
            raise ValidationError("账号不存在！")


class UserdetailForm(FlaskForm):
    name = StringField(
        label='昵称',
        validators=[
            DataRequired("请输入昵称")
        ],
        description="昵称",
        render_kw={
            'class': "form-control",
            'placeholder': "请输入昵称！",
            'autofocus': 'autofocus'
        }
    )
    email = StringField(
        label='邮箱',
        validators=[
            DataRequired("请输入邮箱！"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            'class': "form-control",
            'placeholder': "请输入邮箱！",
        }
    )
    phone = StringField(
        label='电话',
        validators=[
            DataRequired("请输入电话！"),
            Regexp("1[3458]\\d{9}", message="无效手机号码！")
        ],
        description="电话",
        render_kw={
            'class': "form-control",
            'placeholder': "请输入电话！",
        }
    )
    face = FileField(
        label="头像",
        validators=[
            DataRequired("请上传头像！")
        ],
        description="头像"
    )
    info = TextAreaField(
        label="个人简介",
        validators=[
            DataRequired("请输入简介！")
        ],
        description="简介",
        render_kw={
            "class": "form-control",
            "rows": 10
        }
    )
    submit = SubmitField(
        "保存修改",
        render_kw={
            "class": "btn btn-success"
        }
    )


class Changepwd(FlaskForm):
    old_pwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码!")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码",
        }
    )
    new_pwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired("请输入新密码!")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码",
        }
    )
    submit = SubmitField(
        "修改密码",
        render_kw={
            "class": "btn btn-success"
        }
    )

    def validate_old_pwd(self, field):
        from flask import session
        pwd = field.data
        name = session['user']
        user = User.query.filter_by(name=name).first()
        if not user.check_pwd(pwd):
            raise ValidationError("旧密码不正确！")


class CommentForm(FlaskForm):
    content = TextAreaField(
        label="评论",
        validators=[
            DataRequired("请输入评论！")
        ],
        description="评论",
        render_kw={
            "id":"input_content",
        }
    )
    submit = SubmitField(
        label="发布评论",
        render_kw={
            "class": "btn btn-success",
            "id": "btn-sub"
        }
    )
