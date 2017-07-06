# Importing different libraries
import webapp2
import jinja2
import os
import re
import random
import hashlib
import hmac
import time

from google.appengine.ext import db
from string import letters


# Directing where the templates will be
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Setting up jinja2
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Hashed secret for extra layer of security for cookies
SECRET = "1234567890"


# Creates the jinja invorenment
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# Creates a secure cookis with hmac and SECRET
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


# Double checks to see whether or not the cookie is secured
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Main class handler
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(Handler):

    def get(self):
        posts = Post.query().order(Post.created)
        self.render('front.html', posts=posts)


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Variables that set the requirements for user, password and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

PASS_RE = re.compile(r"^.{3,20}$")

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


# Functions that verify whether or not the input is correct for user,
# password and email
def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def users_key(group='default'):
    return db.Key('users', group)


# Class that sets the variables needed for users
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name='default'):
    return db.Key('blogs', name)


# Class that sets the different variables for the posts
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.KeyProperty(kind='user')

    def render(self):
        self._render.text = self.content.replace('\n', '<br>')
        return main.render_str('post.html', p=self)

    def comments(self):
        comments = Comment.query().filter(Comment.post == self.key)
        return comments


# Comment class, where other users can write underneath other posts.
class Comment(db.Model):
    post = db.StringProperty(kind='post')
    content = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    author = db.KeyProperty(kind='user')


# Like class, keeps track of how many people like a specific post.
class Likes(db.Model):
    author = db.KeyProperty(kind='user')
    post = db.StringProperty(kind='post')
    like_counter = db.IntegerProperty()


# Class that calls the main blog link
class BlogFront(Handler):

    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


# Class that redirects the user to a link in which just their post is shown
class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        like_obj = Like.query(Like.post == post.key)

        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return


# Class that handles new posts created by the user
class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.render('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('/')
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please add a subject and content!"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


# Class for new user sign up handler.
class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That is not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That is not a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "The passwords did not match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That is not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        u = User.by_name(self.username)
        if u:
            msg = 'User already exits!'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            key = u.put()
            usercookie = make_secure_val(str(self.username))
            self.response.headers.add_header(
                'Set-Cookie', 'u=%s, Path=/' % usercookie)


class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)

        if u:
            usercookie = make_secure_val(str(username))
            self.response.headers.add_header(
                'Set-Cookie', 'u=%s, Path=/' % usercookie)
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


# List of different webpages and connected to their respective
# classes.
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/welcome', Welcome),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout)],
                              debug=True)
