from flask import Flask,render_template
import config
from app.exts import db
from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app = Flask(__name__)
app.config.from_object(config)
db.init_app(app)

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint,url_prefix='/admin')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('home/404.html'),404

if __name__ == "__main__":
    app.run()


