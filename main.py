# Importing different libraries
import os
import re
import hashlib
import random
import hmac
import webapp2
import jinja2

from string import letters
from google.appengine.ext import db


# Directing where the templates will be
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Setting up jinja2
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Hashed secret for extra layer of security for cookies
SECRET = "1234567890"


# Creating function to make values secured
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())


# Creating function to make sure the values are secured
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Creating function that makes randomiser of letters
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# Creating class that render jinja and short hands some responses
class Handler(webapp2.RequestHandler):

    # Shortens the command to .write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # Render jinja and params for user
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Setting up and securing cookies
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add.headers(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    # Opening and reading the secured cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Sets a secure cookie to the login
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Sets a secure cookie to the logout
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# MainPage class
class MainPage(Handler):

    def get(self):
        self.write('Hello World')


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('blog.html', p=self)


class BlogMainPage(Handler):

    def get(self):
        # posts = db.GqlQuery(
            # 'SELECT * from Post order by created by desc limit 10')
        posts = Post.all().order('-created')
        self.render('blog.html', posts=posts)


class PostPage(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post=post)


class NewPostPage(Handler):

    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('blog/%s' % str(p.key().id()))
        else:
            error = "Please add a subject and content, please."
            self.render('newpost.html', subject=subject,
                        content=content, error=error)


# Verifies for correct characters in the username
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


# Verifies for correct characters in the password
PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


# Verifies for correct characters in the e-mail
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Class for the sign up sheet where the user inputs their information
class SignUpHandler(Handler):

    # Get of the html file signup
    def get(self):
        self.render('signup.html')

    # Posting of information and creation of different variables
    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verifypassword = self.request.get('verifypassword')
        email = self.request.get('email')

        # Creation of parameters in case there is an error and everything does
        # not get erased
        params = dict(username=username, email=email)

        # Checks if the username is valid with the fuctions defined before
        if not valid_username(username):
            params['error_message'] = "That's not a valid username."
            have_error = True

        # Checks if the password is valid with the fuctions defined before
        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != verifypassword:
            params['error_verifypassword'] = "Passwords do NOT match!"
            have_error = True

        # Checks if the email is valid with the fuctions defined before
        if not valid_email(email):
            params['error_email'] = "That't not a valid e-mail."
            have_error = True

        # If there is no error, render welcome page othewise show errors
        if have_error:
            self.render('/signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# Creates a random letters in order to strengthen the hash
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


# Creates the hash and incorporates the salt
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


# Creating class for the user
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # Decorator
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


# Class that redirects the user after the successfully completed signup page
class Signup(SignUpHandler):

    def done(self):
        self.redirect('/welcomepage?username=', self.username)


# Register class handler
class Register(SignUpHandler):

    def done(self):
        userLogin = User.by_name(self.username)
        if userLogin:
            message = "That user already exists!"
            self.render('singup.html', error_username=message)
        else:
            userLogin = User.register(self.username, self.password, self.email)
            userLogin.put()

            self.login(userLogin)
            self.redirect('/welcome')


# Login class handler
class LoginHandler(SignUpHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        userLogin = User.login(username, password)
        if userLogin:
            self.login(userLogin)
            self.redirect('/welcomepage.html')
        else:
            message = "Invalid login!"
            self.render('login.html', error=message)


# Welcome page class that is shown after a user creates a new account or logins
class WelcomePageHandler(SignUpHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')


# Logout class handler
class LogoutHandler(SignUpHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


# List of different webpages and connected to their respective classes.
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogMainPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPostPage),
                               ('/signup', SignUpHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/welcomepage', WelcomePageHandler)],
                              debug=True)
