from . import home
from flask import render_template, redirect, url_for, flash, session, request
from app.home.forms import RegistForm, LoginForm, UserdetailForm, Changepwd, CommentForm
from app.models import User, Userlog, Preview, Tag, Movie, Comment, Moviecol
from werkzeug.utils import secure_filename
from functools import wraps
from app.exts import db
from app.admin.forms import app
from sqlalchemy import or_
import uuid
import os
import datetime


# 登陆限制装饰器
def user_login_decorator(func):
    @wraps(func)
    def decorate_function(*args, **kwargs):
        if session.get("user"):
            return func(*args, **kwargs)
        else:
            return redirect(url_for("home.login", next=request.url))

    return decorate_function


# 上下文应用处理器
@home.context_processor
def user_context_processor():
    user_name = session.get("user")
    if user_name:
        user = User.query.filter_by(name=user_name).first()
        if user:
            return {"user": user}
    else:
        return {}


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


# 会员登陆
@home.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter(
            or_(User.name == data.get('account'), User.email == data.get('account'),
                User.phone == data.get('account'))).first()
        if not user.check_pwd(data.get('pwd')):
            flash("密码不正确，重新输入！", "err")
            return redirect(url_for("home.login"))
        session['user'] = user.name
        session['user_id'] = user.id
        session.permanent = True
        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("home.index", page=1))
    return render_template('home/login.html', form=form)


# 退出登陆
@home.route('/logout/')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('home.login'))


# 会员注册
@home.route('/regist/', methods=['GET', 'POST'])
def regist():
    form = RegistForm()
    if form.validate_on_submit():
        data = form.data
        from werkzeug.security import generate_password_hash
        user = User(
            name=data.get("name"),
            email=data.get("email"),
            phone=data.get("phone"),
            pwd=generate_password_hash(data.get('pwd')),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("恭喜您，注册成功！", "ok")
        return redirect(url_for('home.login'))
    return render_template('home/regist.html', form=form)


# 会员中心
@home.route('/user/', methods=['GET', 'POST'])
@user_login_decorator
def user():
    form = UserdetailForm()
    form.face.validators = []
    user = db.session.query(User).filter_by(id=session.get("user_id")).first()
    if request.method == 'GET':
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        if not os.path.exists(app.config['FC_DIR']):
            os.makedirs(app.config['FC_DIR'])
            os.chmod(app.config['FC_DIR'], 'rw')
        if form.face.data != "":
            file_face = secure_filename(form.face.data.filename)
            user.face = change_filename(file_face)
            form.face.data.save(app.config['FC_DIR'] + user.face)

        name_count = User.query.filter_by(name=data.get("name")).count()
        if name_count == 1 and user.name != data.get("name"):
            flash("昵称已经存在！", 'err')
            return redirect(url_for("home.user"))

        email_count = User.query.filter_by(email=data.get("email")).count()
        if email_count == 1 and user.email != data.get("email"):
            flash("邮箱已经存在！", 'err')
            return redirect(url_for("home.user"))

        phone_count = User.query.filter_by(phone=data.get("phone")).count()
        if phone_count == 1 and user.phone != data.get("phone"):
            flash("电话已经存在！", 'err')
            return redirect(url_for("home.user"))

        user.name = data.get("name")
        user.email = data.get("email")
        user.phone = data.get("phone")
        user.info = data.get("info")
        db.session.add(user)
        db.session.commit()
        flash("修改信息成功！", "ok")
        return redirect(url_for("home.user"))
    return render_template('home/user.html', form=form, user=user)


# 修改密码
@home.route('/pwd/', methods=['GET', 'POST'])
@user_login_decorator
def pwd():
    form = Changepwd()
    if form.validate_on_submit():
        data = form.data
        user = db.session.query(User).filter_by(name=session.get('user')).first_or_404()
        from werkzeug.security import generate_password_hash
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash("修改密码成功！请重新登陆！", 'ok')
        return redirect(url_for('home.logout'))
    return render_template('home/pwd.html', form=form)


# 我的评论
@home.route('/comments/<int:page>/')
def comments(page=None):
    if page is None:
        page = 1
    page_data = db.session.query(Comment).join(User).filter(User.id == session.get("user_id")).order_by(
        Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('home/comments.html', page_data=page_data)


# 会员登陆日志
@home.route('/loginlog/<int:page>', methods=['GET'])
def loginlog(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Userlog).filter_by(user_id=session.get(
        "user_id")).order_by(
        Userlog.addtime.desc()).paginate(
        page=page, per_page=15)
    return render_template('home/loginlog.html', page_data=page_data)


# 添加电影收藏
@home.route('/moviecol/add/', methods=['GET'])
def moviecol_add():
    import json
    uid = request.args.get("uid")
    mid = request.args.get("mid")
    moviecol = db.session.query(Moviecol).join(User).join(Movie).filter(Moviecol.user_id == int(uid),
                                                                        Moviecol.movie_id == int(mid)).count()
    if moviecol == 1:
        data = dict(ok=0)
    if moviecol == 0:
        moviecol = Moviecol(
            user_id=int(uid),
            movie_id=int(mid)
        )
        db.session.add(moviecol)
        db.session.commit()
        data = dict(ok=1)
    return json.dumps(data)


# 电影收藏
@home.route('/moviecol/<int:page>/')
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = db.session.query(Moviecol).join(Movie).join(User).filter(User.id == session.get("user_id"),
                                                             Moviecol.movie_id == Movie.id).order_by(
        Moviecol.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('home/moviecol.html', page_data=page_data)


# 首页
@home.route('/<int:page>/', methods=['GET'])
def index(page=None):
    tags = db.session.query(Tag).all()
    page_data = db.session.query(Movie)

    # 标签
    tid = request.args.get("tid", 0)
    if int(tid) != 0:
        page_data = page_data.filter_by(tag_id=int(tid))

    # 星级
    star = request.args.get("star", 0)
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))

    # 上映时间
    time = request.args.get("time", 0)
    if int(time) != 0:
        if int(time) == 1:
            page_data = page_data.order_by(Movie.addtime.asc())
        else:
            page_data = page_data.order_by(Movie.addtime.desc())

    # 播放量
    pm = request.args.get("pm", 0)
    if int(pm) != 0:
        if int(pm) == 1:
            page_data = page_data.order_by(Movie.playnum.desc())
        else:
            page_data = page_data.order_by(Movie.playnum.asc())

    # 评论数量
    cm = request.args.get("cm", 0)
    if int(cm) != 0:
        if int(cm) == 1:
            page_data = page_data.order_by(Movie.commentnum.desc())
        else:
            page_data = page_data.order_by(Movie.commentnum.asc())

    if page is None:
        page = 1
    page_data = page_data.paginate(page=page, per_page=10)
    p = dict(
        tid=tid,
        star=star,
        time=time,
        pm=pm,
        cm=cm
    )
    return render_template('home/index.html', tags=tags, p=p, page_data=page_data)


# 轮播图
@home.route('/animation/')
def animation():
    data = Preview.query.all()
    return render_template('home/animation.html', data=data)


# 查找页面
@home.route('/search/<int:page>/')
def search(page=None):
    if page is None:
        page = 1
    key = request.args.get("key")
    movie_count = page_data = Movie.query.filter(Movie.title.ilike('%' + key + '%')).count()
    page_data = Movie.query.filter(Movie.title.ilike('%' + key + '%')).order_by(Movie.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('home/search.html', key=key, page_data=page_data, movie_count=movie_count)


# 播放页面
@home.route('/play/<int:id>/<int:page>/', methods=['GET', 'POST'])
def play(id=None, page=None):
    movie = db.session.query(Movie).join(Tag).filter(Movie.id == int(id), Tag.id == Movie.tag_id).first_or_404()
    movie.playnum = movie.playnum + 1
    form = CommentForm()
    if page is None:
        page = 1
    page_data = db.session.query(Comment).join(Movie).join(User).filter(Movie.id == movie.id,
                                                                        User.id == Comment.user_id).order_by(
        Comment.addtime.desc()).paginate(
        page=page, per_page=15)
    db.session.add(movie)
    db.session.commit()
    if session.get("user") and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=movie.id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        flash("发布评论成功！", 'ok')
        db.session.add(movie)
        db.session.commit()
        return redirect(url_for('home.play', id=movie.id, page=1))
    return render_template('home/play.html', movie=movie, form=form, page_data=page_data)
