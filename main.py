# Importing different libraries
import os
import webapp2
import jinja2


# Directing where the templates will be
template_dir = os.path.join(os.path.dirname(__file__), 'templates')

# Setting up jinja2
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


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


# Creating class that render jinja and short hands some responses
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# MainPage class
class MainPage(Handler):

    def get(self):
        self.write("Hello World!")


# Class for the sign up sheet where the user inputs their information
class SignUpHandler(Handler):

    def get(self):
        self.render('signup.html')

    def post(self):
        error = False
        username = self.request.get('username')
        password = self.request.get('password')
        email = self.request.get('email')

    params = dict(username=username, email=email)

    if not valid_username(username):
        params['error_message'] = "That's not a valid username."
        error = True


# List of different webpages and connected to their respective classes.
app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', SignUpHandler),
                               ], debug=True)
