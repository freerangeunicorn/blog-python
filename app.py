from flask import Flask, flash, render_template, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_login import UserMixin, LoginManager, login_required, current_user,login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate



app = Flask(__name__)
loginmanager = LoginManager(app)
FLASK_DEBUG=1
POSTGRES = {
      'user': 'Mai',
      'pw': 'Codeordie2019',
      'db': 'mai',
      'host': 'localhost',
      'port': 5432,
  }
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY']='Zingo'
db = SQLAlchemy(app)
migrate = Migrate(app,db)



class Post(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String)
  body = db.Column (db.String,nullable=False)
  author_name=db.Column(db.String(50),default='anonymous',nullable=False)
  user_id =  db.Column(db.Integer, db.ForeignKey('user.id'))
  created_on = db.Column(db.DateTime, default=db.func.now())
  updated_on = db.Column(db.DateTime, default=db.func.now())
  view_count = db.Column(db.Integer, default=0)
  flags = db.relationship('Flags', backref="post", lazy="dynamic")
  comments = db.relationship('Comments', backref="post", lazy="dynamic")


class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  first_name = db.Column(db.String(120))
  last_name = db.Column(db.String(120))
  email = db.Column(db.String(120), index=True, unique=True)
  password_hash = db.Column(db.String(120), nullable=False)
  flags = db.relationship('Flags', backref="user", lazy="dynamic")
  comments = db.relationship('Comments', backref="user", lazy="dynamic")
  posts = db.relationship('Post', backref="user", lazy="dynamic")
  def set_password(self, password):
    self.password_hash = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.password_hash, password)

class Flags(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  post_id =  db.Column(db.Integer, db.ForeignKey('post.id'))

class Comments(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  body = db.Column (db.String,nullable=False)
  created_on = db.Column(db.DateTime, default=db.func.now())
  updated_on = db.Column(db.DateTime, default=db.func.now())
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
  post_id =  db.Column(db.Integer, db.ForeignKey('post.id'))

db.create_all()


class NewForm(FlaskForm):
  title=StringField('Title', validators=[DataRequired()])
  body=StringField('Text', validators=[DataRequired()])
  author_name=StringField('Name', validators=[DataRequired()])
  submit=SubmitField('Create Post')

class CommentForm(FlaskForm):
  body=StringField('Text', validators=[DataRequired()])
  submit=SubmitField('Comment§')




@loginmanager.user_loader
def load_user(id):
  return User.query.get(int(id))  

@app.route('/')
def hello_world():
    
    return render_template('blogtemplate.html')

@app.route('/posts')
def all_posts():
  posts=Post.query.all()
  return render_template('allposts.html', posts=posts)


@app.route('/posts/<int:post_id>', methods=['POST', 'GET'])
@login_required
def posts(post_id):
  data=Post.query.filter_by(id=post_id).first()
  check=Post.query.filter_by(id=post_id).first()
  check.view_count += 1
  db.session.commit()

  form=CommentForm()
  if request.method == 'POST':
     if form.validate_on_submit():
      comment = Comments(body=form.body.data,
                        user_id=current_user.id,
                        post_id=post_id,
                        )
      db.session.add(comment)
      db.session.commit()
      return redirect (url_for('posts',post_id=post_id))
  return render_template('posts.html', data=data, form=form)

@app.route('/repost/<post_id>')
def report(post_id):
    report=Flags(user_id=current_user.id, post_id=post_id)
    db.session.add(report)
    db.session.commit()
    flash('Your report has been sent', 'success')
  
    return redirect(url_for('profile'))

@app.route('/create', methods=['POST', 'GET'])
@login_required
def create_post():
  form = NewForm()  ###### FAIL
  if request.method == 'POST':  
    if form.validate_on_submit():
      new_post = Post(title=form.title.data,
                        body=form.body.data,
                        author_name=form.author_name.data,
                        user_id=current_user.id)
      db.session.add(new_post)
      db.session.commit()
      return redirect(url_for('posts'))
    else:
      flash('Please, fill in the missing space')
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
  posts = Post.query.all()
  return render_template('profile.html', posts=posts)


if (__name__) == '__main__':
    app.run(debug=True)
    


