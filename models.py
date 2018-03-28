from datetime import datetime
from exts import db


# 会员
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    name = db.Column(db.String(100), nullable=False, unique=True)  # 昵称
    pwd = db.Column(db.String(100), nullable=False)  # 密码
    email = db.Column(db.String(100), nullable=False, unique=True)  # 邮箱
    phone = db.Column(db.String(11), nullable=False, unique=True)  # 电话
    info = db.Column(db.Text)  # 个性简介
    face = db.Column(db.String(255), unique=True)  # 头像
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    uuid = db.Column(db.String(255), unique=True)  # 唯一标识符
    userlogs = db.relationship('Userlog', backref=db.backref('user'))  # 会员日志外键关联
    comments = db.relationship('Comment', backref=db.backref('user'))  # 评论外键关联
    moviecols = db.relationship('Moviecol', backref=db.backref('user'))  # 电影收藏外键关联

    def __repr__(self):
        return "<User %r>" % self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


# 会员登陆日志
class Userlog(db.Model):
    __tablename__ = "userlog"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 所属会员
    ip = db.Column(db.String(100))  # 登陆ip
    addtime = db.Column(db.DateTime, default=datetime.now)  # 登陆时间

    def __repr__(self):
        return "<userlog %r>" % self.id


# 标签
class Tag(db.Model):
    __tablename__ = "tag"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 标签名字
    addtime = db.Column(db.DateTime, default=datetime.now, index=True)  # 标签创建时间
    movies = db.relationship('Movie', backref=db.backref('tag'))  # 电影外键关联

    def __repr__(self):
        return "<Tag %r>" % self.name


# 电影
class Movie(db.Model):
    __tablename__ = 'movie'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 电影编号
    title = db.Column(db.String(255), unique=True)  # 电影名称
    url = db.Column(db.String(255), unique=True)  # 电影播放路径
    info = db.Column(db.Text)  # 电影简介
    logo = db.Column(db.String(255), unique=True)  # 电影封面
    star = db.Column(db.SmallInteger)  # 电影星级
    playnum = db.Column(db.BigInteger)  # 电影播放量
    commentnum = db.Column(db.BigInteger)  # 电影评论数
    tag_id = db.Column(db.Integer, db.ForeignKey("tag.id"))  # 所属标签
    area = db.Column(db.String(255))  # 电影上映地区
    release_time = db.Column(db.DateTime)  # 电影上映时间
    length = db.Column(db.String(100))  # 电影时长
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 电影添加时间
    comments = db.relationship('Comment', backref=db.backref('movie'))  # 评论外键关联
    moviecols = db.relationship('Moviecol', backref=db.backref('movie'))  # 电影收藏外键关联

    def __repr__(self):
        return "<Movie %r>" % self.title


# 上映预告
class Preview(db.Model):
    __tablename__ = "preview"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 电影编号
    title = db.Column(db.String(255), unique=True)  # 电影名称
    logo = db.Column(db.String(255), unique=True)  # 电影封面
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 电影添加时间

    def __repr__(self):
        return "<Preview %r>" % self.title


# 评论
class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 电影编号
    content = db.Column(db.Text)  # 内容
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))  # 所属电影
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))  # 所属用户
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 评论添加时间

    def __repr__(self):
        return "<Comment %r>" % self.id


# 电影收藏
class Moviecol(db.Model):
    __tablename__ = 'moviecol'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    content = db.Column(db.Text)  # 内容
    movie_id = db.Column(db.Integer, db.ForeignKey("movie.id"))  # 所属电影
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))  # 所属用户
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间

    def __repr__(self):
        return "<Moviecol %r>" % self.id


# 权限
class Auth(db.Model):
    __tablename__ = 'auth'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    url = db.Column(db.String(255), unique=True)  # 路径
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间

    def __repr__(self):
        return "<Auth %r>" % self.name


# 角色
class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    auths = db.Column(db.String(600))
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    admins = db.relationship('Admin', backref=db.backref('role'))

    def __repr__(self):
        return "<Role %r>" % self.name


# 管理员
class Admin(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    name = db.Column(db.String(100), nullable=False, unique=True)  # 管理员账号
    pwd = db.Column(db.String(100), nullable=False)  # 管理员密码
    is_super = db.Column(db.SmallInteger)  # 是否为超级管理员 0为超级管理员
    role_id = db.Column(db.Integer, db.ForeignKey("role.id"))  # 所属角色
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    adminlogs = db.relationship('Adminlog', backref=db.backref('admin'))  # 管理员登陆日志外键关联
    oplogs = db.relationship('Oplog', backref=db.backref('admin'))  # 管理员操作日志外键关联

    def __repr__(self):
        return "<Admin %r>" % self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


# 管理员登陆日志
class Adminlog(db.Model):
    __tablename__ = "adminlog"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))  # 所属管理员
    ip = db.Column(db.String(100))  # 登陆ip
    addtime = db.Column(db.DateTime, default=datetime.now)  # 登陆时间

    def __repr__(self):
        return "<adminlog %r>" % self.id


# 操作日志
class Oplog(db.Model):
    __tablename__ = "oplog"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))  # 所属管理员
    ip = db.Column(db.String(100))  # 登陆ip
    reason = db.Column(db.String(600))  # 操作原因
    addtime = db.Column(db.DateTime, default=datetime.now)  # 登陆时间

    def __repr__(self):
        return "<Oplog %r>" % self.id
