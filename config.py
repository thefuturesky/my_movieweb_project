import os
DEBUG=True

SECRET_KEY = os.urandom(24)

UP_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)),"static/uploads/")
FC_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)),"static/uploads/user/")

USERNAME='root'
PASSWORD='python'
HOSTNAME='127.0.0.1'
PORT='3306'
DATABASE='movie'

SQLALCHEMY_DATABASE_URI="mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8".format(USERNAME,PASSWORD,HOSTNAME,PORT,DATABASE)

SQLALCHEMY_TRACK_MODIFICATIONS= False