import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'FireAndBlood'
# when bugs are fixed I intend to let all users see who else is logged in
# logged_in = []


# currently unused function that changes a list to a string
def string_list(change):
    return str(change).replace('[','').replace(']','').replace("'"," ")


# takes templates and renders html
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# uses the variable secret to make a secure value
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


# verification of the secure value vs secret
def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


# Handler Class, uses webapp2.RequestHandler and its helper methods
class Handler(webapp2.RequestHandler):
    # writes output to client
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # renders HTML using template
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # sets the browser's cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # reads the broswer's cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # makes a secure cookie according to user ID
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # removes login credentials from browser's cookie
    def logout(self):
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # verification of credentials by reading browser cookie data
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# this html string establishes a link to the blog front from the landing page,
# which I intend to do a little more with
land_html = """
<body>
<button style="position:absolute;top:45%;right:40%;" onclick="blog()">
    <h1>Aerobic Entropy Blog</h1>
</button>

<script type="text/javascript">
function blog() {
    window.location.href = window.location.href + "blog/"
    };
</script>
</body>
"""
# these two strings add a button that appears and changes in function depending
# on if a user is logged in
logout_html = """
<a href="#" class="btn btn-primary" onclick="logout()">Logout</a>
"""

login_html = """
<a href="#" class="btn btn-primary" onclick="login()">Login</a>
"""

# handler for landing page, writes the html above with a link to blog
class LandPage(Handler):
    def get(self):
        self.write(land_html)


def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))


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


def findUser(self):
    user = User.by_id(self.user_id)
    return user.name


# User class
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    def __str__(self):
        return User.name

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


# Post class
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty()
    username = db.StringProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

    def findUser(self):
        user = User.by_id(self.user_id)
        return user.name


# comment class, much like post class, but also has a post_id property
class Comment(db.Model):
    comment = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def findUser(self):
        user = User.by_id(self.user_id)
        return user.name


# Like class, has user and post properties to track identities
class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def findUser(self):
        user = User.by_id(self.user_id)
        return user.name


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# front class uses Handler and its methods
class BlogFront(Handler):
    def get(self):
        logout = self.request.get('logout')
        posts = db.GqlQuery("SELECT * FROM Post " +
                            "ORDER BY created DESC limit 10")
        if not self.user:
            self.render('front.html', posts=posts, logout="", login=login_html,
             you='')
        else:
            uid = int(self.read_secure_cookie('user_id'))
            user = User.by_id(uid)
            you = user.name
            self.render('front.html', posts=posts, logout=logout_html, login="",
             you=you)
# namelist=string_list(list(set(logged_in))) < future updates bug fix needed


# PostPage class uses Handler and it's methods
class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        error = self.request.get('error')

        if not post:
            self.error(404)
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post, error=error, comments=comments,
         likes_count=likes.count())

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""

# checks if the browser is logged in
        if(self.user):
            # if so, it allows the user to comment
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()

            # if so, is also allows the user to like a post
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                # if the user's id matched the post's user id, throws an error
                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=Sorry, you can't like your " +
                                  "own post")
                    return
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()
# if not, it redirects to login
        else:
            self.redirect("/login?error=Please login...")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post, comments=comments,
            likes_count=likes.count(), new=c)


# NewPost class uses handler and it's methods
class NewPost(Handler):
    def get(self):
        # if a user it renders the template
        if self.user:
            self.render("newpost.html")
            # if not regirects to login
        else:
            self.redirect("/login?error=Please login...")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            uid = int(self.read_secure_cookie('user_id'))
            self.user = uid and User.by_id(int(uid))
            u = str(self.user.name)
            p = Post(parent=blog_key(), subject=subject, content=content,
                         user_id=uid, username=u)
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "Each post requires a subject and an content!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Signup class uses handler and it's methods to help Register make new users
class Signup(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


# Register class, uses Signup class and it's methods to create new users
class Register(Signup):
    def done(self):
        # if the a user already has that name displays the error msg
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        # otherwise, create a new user and redirect to login welcome
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


# Login class, uses handler and its methods to login a user
class Login(Handler):
    def get(self):
        error = self.request.get('error')
        self.render('login-form.html', error=error)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid Login'
            self.render('login-form.html', error=msg)


# Logout class, uses handler and its methods to logout a user
class Logout(Handler):
    def get(self):
        ''' saved for later updates
        logged_in.remove(str(self.user.name))
        '''
        self.logout()
        self.redirect('/login')


# Welcome class, uses handler and its methods to welcome a user
class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
            ''' saved for future updates
            logged_in.append(str(self.user.name))
            '''
        # try to navigate to this page while logged out, and it redirects you
        else:
            self.redirect('/login')


# EditPost class, uses handler and its methods to edit posts
class EditPost(Handler):
    def get(self, post_id):
        # checks if user
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # if so, check if that post was created by that user
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            # if not, redirect to that post and display error message
            else:
                self.redirect("/blog/" + post_id + "?error=Only the creator "+
                              "can edit a post")
        # if not, redirects to login
        else:
            self.redirect("/login?error=Log in to edit post")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "There must be a subject and content..."
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


class DeletePost(Handler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            # only allow the creator of a post to delete it
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/blog/?")
            # if the user isn't the creator, display an error msg
            else:
                self.redirect("/blog/" + post_id + "?error=Only the " +
                              "creator can delete their post.")
        # redirect to login if not a user
        else:
            self.redirect("/login?error=Log in to delete posts...")


class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            # if the comment user id is the sam as the logged in user, delete
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            # if not, display an error
            else:
                self.redirect("/blog/" + post_id + "?error=That is " +
                              "not your comment")
        # if not logged in, redirect to login with error msg
        else:
            self.redirect("/login?error=You must log in to " +
                          "delete your comment")


class EditComment(Handler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            # if the user id matches the comment's creator, allow edit
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            # otherwise display the error msg
            else:
                self.redirect("/blog/" + post_id +
                              "?error=That is not your comment")
        # send to login page if the browser is not logged in
        else:
            self.redirect("/login?error=Please log in to " +
                          "edit a post")

    def post(self, post_id, comment_id):
        # if you try to post a comment without being logged in, redirect login
        if not self.user:
            self.redirect('/login?error=Please log in...')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


app = webapp2.WSGIApplication([('/', LandPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ],
                              debug=True)
