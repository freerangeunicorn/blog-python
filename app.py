from flask import Flask, flash, render_template, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_login import UserMixin, LoginManager, login_required, current_user,login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash



app = Flask(__name__)
loginmanager = LoginManager(app)
FLASK_DEBUG=1
POSTGRES = {
      'user': 'Mai',
      'pw': '',
      'db': 'mai',
      'host': 'localhost',
      'port': 5432,
  }
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY']='Zingo'
db = SQLAlchemy(app)
db.create_all()


class Post(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String)
  body = db.Column (db.String,nullable=False)
  author_name=db.Column(db.String(50),default='anonymous',nullable=False)
  created_on = db.Column(db.DateTime, default=db.func.now())
  updated_on = db.Column(db.DateTime, default=db.func.now())

class PostForm(FlaskForm):
  title=StringField('Title', validators=[DataRequired()])
  body=StringField('Text', validators=[DataRequired()])
  author_name=StringField('Name', validators=[DataRequired()])
  submit=SubmitField('Create Post')

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  first_name = db.Column(db.String(120))
  last_name = db.Column(db.String(120))
  email = db.Column(db.String(120), index=True, unique=True)
  password_hash = db.Column(db.String(120), nullable=False)
  def set_password(self, password):
    self.password_hash = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password_hash, password)


db.create_all()


@loginmanager.user_loader
def load_user(id):
  return User.query.get(int(id))  

@app.route('/')
def hello_world():
    return 'home!'

@app.route('/posts')
def posts():
    return render_template('posts.html')

@app.route('/create')
def create_post():
  form=PostForm()
  return render_template('create.html', form=form)

@app.route('/login', methods=['POST', 'GET'])
def login():
  if request.method == 'POST':
    user = User.query.filter_by(email=request.form["email"]).first()
    if user.check_password(request.form["password"]):
      login_user(user)
      return redirect(url_for('profile'))
    else:
      flash('Sorry, your username and/or password is incorrect.', 'danger')
    # return redirect(url_for('login'))
  return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
  logout_user()
  return redirect(url_for('login'))

@app.route('/signup',methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
      check=User.query.filter_by(email=request.form['email']).first()
      if not check:
        new_user = User(email=request.form['email'],
                        first_name=request.form['first_name'],
                        last_name=request.form['last_name'])
        new_user.set_password(request.form['password'])
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
      else:
        flash('This email already exists')
        return redirect(url_for('signup'))
    return render_template('signup.html')

@app.route('/profile')
@login_required
def profile():
  return render_template('profile.html')


if (__name__) == '__main__':
    app.run(debug=True)
    


