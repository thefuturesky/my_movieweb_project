from . import admin
from flask import render_template, redirect, url_for, flash, session, request, abort
from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, PwdForm, AuthForm, RoleForm, AdminForm
from app.models import Admin, Tag, Movie, Preview, User, Comment, Moviecol, Oplog, Adminlog, Userlog, Auth, Role
from functools import wraps
from app.exts import db
from app.movie import app
from werkzeug.utils import secure_filename
import os
import datetime
import uuid


# 登陆装饰器
def admin_login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if session.get('admin'):
            return func(*args, **kwargs)
        else:
            return redirect(url_for('admin.login', next=request.url))

    return decorated_function

# 权限控制装饰器
def admin_auth(func):
    @wraps(func)
    def decorated_function(*args,**kwargs):
        admin = db.session.query(Admin).join(Role).filter(Role.id == Admin.role_id,
                Admin.id == session.get('admin_id')).first()
        auths = admin.role.auths
        auths = list(map(lambda x:int(x),auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if v.id == val]
        rule = str(request.url_rule)
        if rule not in urls:
            abort(404)
        return func(*args,**kwargs)
    return decorated_function


# 操作日志数据添加
def operate_log(content):
    oplog = Oplog(
        admin_id=session.get('admin_id'),
        ip=request.remote_addr,
        reason=content
    )
    db.session.add(oplog)
    db.session.commit()


# 上下文应用处理器
@admin.context_processor
def tpl_extra():
    # data = dict(
    #     online_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # )
    return {'online_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    # return data


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@admin.route('/')
@admin_login_required
def index():
    return render_template('admin/index.html')


# 后台登陆
@admin.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            flash("密码错误", "err")
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        session.permanet = True
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


# 退出登陆
@admin.route('/logout/')
@admin_login_required
def logout():
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


# 修改密码
@admin.route('/pwd/', methods=['GET', 'POST'])
@admin_login_required
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = db.session.query(Admin).filter_by(name=session.get('admin')).first_or_404()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功！请重新登陆！", 'ok')
        operate_log("修改密码")
        return redirect(url_for('admin.logout'))
    return render_template('admin/pwd.html', form=form)


# 添加标签
@admin.route('/tag/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = db.session.query(Tag).filter_by(name=data['name']).count()
        if tag == 1:
            flash("标签已存在", "err")
            return redirect(url_for('admin.tag_add'))
        else:
            tag = Tag(
                name=data['name']
            )
            db.session.add(tag)
            db.session.commit()
            flash("添加标签成功！", "ok")
            operate_log("添加标签:%s" % data['name'])
            return redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


# 标签列表
@admin.route('/tag/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def tag_list(page=None):
    if page is None:
        page = 1
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/tag_list.html', page_data=page_data)


# 删除标签
@admin.route('/tag/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def tag_del(id=None):
    tag = db.session.query(Tag).filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功！", "ok")
    operate_log("删除标签:%s" % tag.name)
    return redirect(url_for('admin.tag_list', page=1))


# 编辑标签
@admin.route('/tag/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def tag_edit(id=None):
    tag = db.session.query(Tag).filter_by(id=id).first()
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        if tag_count:
            flash("标签已存在", "err")
            return redirect(url_for('admin.tag_edit', id=id))
        else:
            tag.name = data['name']
            db.session.add(tag)
            db.session.commit()
            flash("修改标签成功！", "ok")
            operate_log("修改标签:%s" % tag.name)
            return redirect(url_for('admin.tag_edit', id=id))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


# 添加电影
@admin.route('/movie/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def movie_add():
    form = MovieForm()
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        movie = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            playnum=0,
            commentnum=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            length=data['length'],
            release_time=data['release_time']
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", "ok")
        operate_log("添加电影:%s" % data['title'])
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


# 电影列表
@admin.route('/movie/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = db.session.query(Movie).order_by(Movie.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/movie_list.html', page_data=page_data)


# 删除电影
@admin.route('/movie/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def movie_del(id=None):
    movie = db.session.query(Movie).filter_by(id=id).first_or_404()
    db.session.delete(movie)
    db.session.commit()
    flash("删除电影成功！", "ok")
    operate_log("删除电影:%s" % movie.title)
    return redirect(url_for('admin.movie_list', page=1))


# 编辑电影
@admin.route('/movie/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def movie_edit(id=None):
    movie = db.session.query(Movie).filter_by(id=id).first()
    form = MovieForm()
    form.url.validators = []
    form.logo.validators = []
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count:
            flash("电影名称已存在", "err")
            return redirect(url_for('admin.movie_edit', id=id))
        else:
            if not os.path.exists(app.config['UP_DIR']):
                os.makedirs(app.config['UP_DIR'])
                os.chmod(app.config['UP_DIR'], 'rw')

            if form.url.data != "":
                file_url = secure_filename(form.url.data.filename)
                movie.url = change_filename(file_url)
                form.url.data.save(app.config['UP_DIR'] + movie.url)

            if form.logo.data != "":
                file_logo = secure_filename(form.logo.data.filename)
                movie.logo = change_filename(file_logo)
                form.logo.data.save(app.config['UP_DIR'] + movie.logo)

            movie.title = data['title']
            movie.info = data['info']
            movie.star = int(data['star'])
            movie.tag_id = int(data['tag_id'])
            movie.area = data['area']
            movie.length = data['length']
            movie.release_time = data['release_time']
            db.session.add(movie)
            db.session.commit()
            flash("修改电影成功！", "ok")
            operate_log("修改电影:%s" % data['title'])
            return redirect(url_for('admin.movie_edit', id=id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


# 添加预告
@admin.route('/preview/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], 'rw')
        logo = change_filename(file_logo)
        form.logo.data.save(app.config['UP_DIR'] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash("添加电影预告成功！", "ok")
        operate_log("添加预告:%s" % data['title'])
    return render_template('admin/preview_add.html', form=form)


# 预告列表
@admin.route('/preview/list/<int:page>/')
@admin_login_required
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(Preview.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/preview_list.html', page_data=page_data)


# 删除预告
@admin.route('/preview/del/<int:id>/', methods=['GET'])
@admin_login_required
def preview_del(id=None):
    preview = db.session.query(Preview).filter_by(id=id).first_or_404()
    db.session.delete(preview)
    db.session.commit()
    flash("删除预告成功！", "ok")
    operate_log("删除预告:%s" % preview.title)
    return redirect(url_for('admin.preview_list', page=1))


# 修改电影预告
@admin.route('/preview/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def preview_edit(id=None):
    preview = db.session.query(Preview).filter_by(id=id).first_or_404()
    form = PreviewForm()
    form.logo.validators = []
    if form.validate_on_submit():
        data = form.data
        preview_count = Preview.query.filter_by(title=data['title']).count()
        if preview_count:
            flash("预告名称已经存在！", "err")
            return redirect(url_for('admin.preview_edit', id=id))
        else:
            if not os.path.exists(app.config['UP_DIR']):
                os.makedirs(app.config['UP_DIR'])
                os.chmod(app.config['UP_DIR'], 'rw')

            if form.logo.data != "":
                file_logo = secure_filename(form.logo.data.filename)
                preview.logo = change_filename(file_logo)
                form.logo.data.save(app.config['UP_DIR'] + preview.logo)

            preview.title = data['title']
            db.session.add(preview)
            db.session.commit()
            flash("修改预告成功！", "ok")
            operate_log("修改预告:%s" % preview.title)
            return redirect(url_for('admin.preview_edit', id=id))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


# 查看用户
@admin.route('/user/view/<int:id>/')
@admin_login_required
@admin_auth
def user_view(id=None):
    user = db.session.query(User).filter_by(id=id).first_or_404()
    return render_template('admin/user_view.html', user=user)


# 删除用户
@admin.route('/user/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def user_del(id=None):
    user = db.session.query(User).filter_by(id=id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    flash("删除会员成功！", "ok")
    operate_log("删除用户:%s" % user.name)
    return redirect(url_for('admin.user_list', page=1))


# 用户列表
@admin.route('/user/list/<int:page>/')
@admin_login_required
@admin_auth
def user_list(page=None):
    if page == None:
        page = 1
    page_data = User.query.order_by(User.addtime.desc()).paginate(page=page, per_page=10)
    for user in page_data.items:
        type(user.face)
        print(user.face)
    return render_template('admin/user_list.html', page_data=page_data)


# 评论列表
@admin.route('/comment/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def comment_list(page=None):
    if page == None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(Movie.id == Comment.movie_id,
                                                            User.id == Comment.user_id).order_by(
        Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/comment_list.html', page_data=page_data)


# 删除评论
@admin.route('/comment/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def comment_del(id=None):
    comment = db.session.query(Comment).get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除评论成功！", "ok")
    operate_log("删除评论:%s" % comment.content)
    return redirect(url_for('admin.comment_list', page=1))


# 电影收藏
@admin.route('/moviecol/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def moviecol_list(page=None):
    if page == None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(Movie.id == Moviecol.movie_id,
                                                             User.id == Moviecol.user_id).order_by(
        Moviecol.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/moviecol_list.html', page_data=page_data)


# 删除电影收藏
@admin.route('/moviecol/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def moviecol_del(id=None):
    moviecol = db.session.query(Moviecol).join(Movie, Moviecol.movie_id == Movie.id).filter(Moviecol.id == id).first()
    title = moviecol.movie.title
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功！", "ok")
    operate_log("删除电影收藏:%s" % title)
    return redirect(url_for('admin.moviecol_list', page=1))


# 会员登陆日志列表
@admin.route('/userloginlog/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def userloginlog_list(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Userlog).join(User, User.id == Userlog.user_id).order_by(Userlog.id).paginate(
        page=page, per_page=15)
    return render_template('admin/userloginlog_list.html', page_data=page_data)


# 管理员登陆日志列表
@admin.route('/adminloginlog/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def adminloginlog_list(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Adminlog).join(Admin, Admin.id == Adminlog.admin_id).order_by(
        Adminlog.addtime.desc()).paginate(page=page, per_page=15)
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


# 操作日志列表
@admin.route('/oplog/list/<int:page>/', methods=['GET'])
@admin_login_required
@admin_auth
def oplog_list(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Oplog).join(Admin, Admin.id == Oplog.admin_id).order_by(Oplog.addtime.desc()).paginate(
        page=page, per_page=15)
    return render_template('admin/oplog_list.html', page_data=page_data)


# 角色列表
@admin.route('/role/list/<int:page>/')
@admin_login_required
@admin_auth
def role_list(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Role).order_by(Role.addtime.desc()).paginate(page=page, per_page=6)
    return render_template('admin/role_list.html', page_data=page_data)


# 角色添加
@admin.route('/role/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def role_add():
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data["name"],
            auths=",".join(map(lambda x: str(x), data['auths']))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
    return render_template('admin/role_add.html', form=form)


# 删除角色
@admin.route('/role/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def role_del(id=None):
    role = db.session.query(Role).filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("删除角色成功！", "ok")
    operate_log("删除角色:%s" % role.name)
    return redirect(url_for('admin.role_list', page=1))


# 编辑角色
@admin.route('/role/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def role_edit(id=None):
    role = db.session.query(Role).filter_by(id=id).first()
    form = RoleForm()
    if request.method == "GET":
        form.auths.data = list(map(lambda x: int(x), role.auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role.name = data['name']
        role.auths = ",".join(map(lambda x: str(x), data['auths']))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！", "ok")
        operate_log("修改角色:%s" % role.name)
        return redirect(url_for('admin.role_edit', id=id))
    return render_template('admin/role_edit.html', form=form, role=role)


# 权限列表
@admin.route('/auth/list/<int:page>/', methods=['GET'])
@admin_login_required
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = db.session.query(Auth).order_by(Auth.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('admin/auth_list.html', page_data=page_data)


# 权限添加
@admin.route('/auth/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", "ok")
        operate_log("添加权限:%s" % data['name'])
    return render_template('admin/auth_add.html', form=form)


# 编辑权限
@admin.route('/auth/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_required
def auth_edit(id=None):
    auth = db.session.query(Auth).filter_by(id=id).first()
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！", "ok")
        operate_log("修改权限:%s" % auth.name)
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


# 删除权限
@admin.route('/auth/del/<int:id>/', methods=['GET'])
@admin_login_required
@admin_auth
def auth_del(id=None):
    auth = db.session.query(Auth).filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！", "ok")
    operate_log("删除权限:%s" % auth.name)
    return redirect(url_for('admin.auth_list', page=1))


# 管理员列表
@admin.route('/admin/list/<int:page>/')
@admin_login_required
@admin_auth
def admin_list(page=None):
    if page == None:
        page = 1
    page_data = db.session.query(Admin).join(Role,Role.id == Admin.role_id).order_by(Admin.addtime.desc()).paginate(
        page=page, per_page=10)
    return render_template('admin/admin_list.html', page_data=page_data)


# 添加管理员
@admin.route('/admin/add/', methods=['GET', 'POST'])
@admin_login_required
@admin_auth
def admin_add():
    form = AdminForm()
    if form.validate_on_submit():
        data = form.data
        from werkzeug.security import generate_password_hash
        admin = Admin(
            name = data['name'],
            pwd = generate_password_hash(data['pwd']),
            role_id = data['role_id'],
            is_super = 1
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！","ok")
        operate_log("添加管理员:%s" % data['name'])
    return render_template('admin/admin_add.html', form=form)
