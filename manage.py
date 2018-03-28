from exts import db
from movie import app
from flask_script import Manager
from flask_migrate import Migrate,MigrateCommand
from models import User,Userlog,Tag,Movie,Preview,Comment,Moviecol,Auth,Role,Admin,Adminlog,Oplog


manager=Manager(app)

migrate = Migrate(app,db)

manager.add_command('db',MigrateCommand)

if __name__ == "__main__":
    manager.run()