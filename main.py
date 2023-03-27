from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.app_context().push()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES


class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000),nullable=False)
    email = db.Column(db.String(100),unique=True,nullable=False)
    password = db.Column(db.String(100),nullable=False)

    # ***************Parent Relationship*************#
    posts = relationship("BlogPost", back_populates="users")
    comments = relationship("Comment", back_populates="users")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ***************Child Relationship*************#
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    users = relationship("User", back_populates="posts")

    # ***************Parent Relationship*************#
    comments = relationship("Comment",back_populates="posts")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)

    # ***************Child Relationship*************#
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    users = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    posts = relationship("BlogPost", back_populates="comments")





#db.create_all()

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)



def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != "1":
            return abort(403)
        return func(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register',methods=["GET","POST"])
def register():
    register_form = RegisterForm()
    if request.method == "POST":
        name = request.form["name"]
        all_users = User.query.all()
        all_emails = [user.email for user in all_users]
        email = request.form["email"]
        if email in all_emails:
            flash("You have already sign up with this email, please log in!")
            return redirect(url_for("login"))
        password = generate_password_hash(request.form["password"],method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=name, email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html",form=register_form)


@app.route('/login',methods=["GET",'POST'])
def login():
    login_form = LoginForm()
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user == None:
            flash("The email doesnt exist, please try again")
            return redirect(url_for("login"))
        if not check_password_hash(user.password,request.form["password"]):
            flash("Incorrect password, please try again!")
            return redirect(url_for("login"))
        login_user(user)
        return redirect(url_for("get_all_posts"))


    return render_template("login.html",form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if request.method == "POST" and form.validate_on_submit():
        if current_user.is_authenticated :
            new_comment = Comment(
            body= request.form["body"],
            users = current_user,
            posts = requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to log in or register to comment")
            return redirect(url_for("login"))

    comments = BlogPost.query.get(post_id).comments

    return render_template("post.html", post=requested_post, form=form,comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=["GET","POST"])
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=["GET","POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method =="POST" and form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author= current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            users= current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("show_post", post_id=new_post.id))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>",methods=["GET","POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>",methods=["GET","POST"])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
