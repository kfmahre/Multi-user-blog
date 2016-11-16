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


def string_list(change):
    """
    string_list: function that changes a list to a string, currently unused
    """
    return str(change).replace('[', '').replace(']', '').replace("'", " ")


def render_str(template, **params):
    """
    render_str: takes templates and renders html
    """
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    """
    make_secure_val: uses the variable secret to make val secure
    """
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())


# verification of the secure value vs secret
def check_secure_val(h):
    """
    check_secure_val: compares h to
    """
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    """
    Handler: uses webapp2.RequestHandler and its helper methods
    """
    def write(self, *a, **kw):
        """
        write: writes output to client
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
        render_str: renders HTML using template
        """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        """
        set_secure_cookie: sets the browser's cookie
        """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """
        read_secure_cookie: reads the broswer's cookie
        """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """
        login: makes a secure cookie according to user ID
        """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
        logout: removes login credentials from browser's cookie
        """
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
        initialize: verifies credentials by reading browser cookie data
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

# This html string establishes a link to the blog front from the landing page,
# which I intend to do a little more with later
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
"""
These two strings add a button that appears and changes in function depending
on if a user is logged in or not.
"""
logout_html = """
<a href="#" class="btn btn-primary" onclick="logout()">Logout</a>
"""

login_html = """
<a href="#" class="btn btn-primary" onclick="login()">Login</a>
"""


class LandPage(Handler):
    """
    LandPage: writes land_html
    """
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


class User(db.Model):
    """
    User: name, pw_hash, email properties
    """
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


class Post(db.Model):
    """
    Post: subject, content, created, last_modified, user_id, and username
    properties.
    """
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


class Comment(db.Model):
    """
    Comment: like posts, but also has a post_id property
    """
    comment = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def findUser(self):
        user = User.by_id(self.user_id)
        return user.name


class Like(db.Model):
    """
    Like: has user and post properties to track identities
    """
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def findUser(self):
        user = User.by_id(self.user_id)
        return user.name


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogFront(Handler):
    """
    BlogFront: uses Handler and it's methods to display front.html
    """
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
            self.render('front.html', posts=posts, logout=logout_html,
                        login="", you=you)


class PostPage(Handler):
    """
    PostPage: uses Handler and it's methods to display posts
    """
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

        self.render("permalink.html", post=post, error=error,
                    comments=comments, likes_count=likes.count())

    def post(self, post_id):
        """
        post: If logged in, user can comment or like a post. If the user's id
        matches the post's user id, it displays an error msg. If not logged in,
        redirect to login.
        """
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        c = ""

        if(self.user):
            if(self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()

            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=Sorry, you can't like your " +
                                  "own post")
                    return
                elif likes.count() == 0:
                    l = Like(parent=blog_key(), user_id=self.user.key().id(),
                             post_id=int(post_id))
                    l.put()
        else:
            self.redirect("/login?error=Please login...")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")

        likes = db.GqlQuery("select * from Like where post_id="+post_id)

        self.render("permalink.html", post=post, comments=comments,
                    likes_count=likes.count(), new=c)


class NewPost(Handler):
    """
    NewPost: uses handler and it's methods to create new posts
    """
    def get(self):
        """
        get: Render newpost if logged in, if not logged in,
        redirect to login
        """
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login?error=Please login...")

    def post(self):
        """
        post: If not logged in, redirects back to blog. Creates new post if
        there is a subject and content when submitted.
        """
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


class Signup(Handler):
    """
    Signup: uses Handler and its methods to help Register make new users.
    """
    def get(self):
        """
        get: render signup-form
        """
        self.render("signup-form.html")

    def post(self):
        """
        post: takes values and compares them to parameters, that, if they pass
        conditions, will allow a user to register.
        """
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


class Register(Signup):
    """
    Register: uses Signup class and it's methods to create new users
    """
    def done(self):
        """
        done: If a user already has the chosen name, display an error msg.
        Otherwise, create a new user and redirect to welcome.
        """
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


class Login(Handler):
    """
    Login: uses Handler and its methods to login a user
    """
    def get(self):
        """
        get: renders login form and displays any error msgs
        """
        error = self.request.get('error')
        self.render('login-form.html', error=error)

    def post(self):
        """
        post: redirects to welcome, or back to login with error msg.
        """
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid Login'
            self.render('login-form.html', error=msg)


class Logout(Handler):
    """
    Logout: uses Handler and its methods to logout a user
    """
    def get(self):
        """
        get: logs user out and redirects to login
        """
        self.logout()
        self.redirect('/login')


class Welcome(Handler):
    """
    Welcome: uses Handler and its methods to welcome a user.
    """
    def get(self):
        """
        get: If logged in, render welcome. If not, redirect to login.
        """
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/login')


class EditPost(Handler):
    """
    EditPost: uses Handler and its methods to edit posts
    """
    def get(self, post_id):
        """
        get: Checks if user. If so, check if that post was created by that
        user. If not, redirect to that post and display error message. If not
        logged in, redirects to login.
        """
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=Only the creator " +
                              "can edit a post")
        else:
            self.redirect("/login?error=Log in to edit post")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            if post.user_id == self.user.key().id():
                post.put()
                self.redirect('/blog/%s' % post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=Only the creator " +
                              "can edit a post")
        else:
            error = "There must be a subject and content..."
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


class DeletePost(Handler):
    """
    DeletePost: uses Handler and its helper classes to delete posts
    """
    def get(self, post_id):
        """
        get: If logged in, allow the creator of a post to delete it. If the
        user isn't the creator of the post, display an error msg. If browser
        isn't logged in, redirect to login.
        """
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/blog/?")
            else:
                self.redirect("/blog/" + post_id + "?error=Only the " +
                              "creator can delete their post.")
        else:
            self.redirect("/login?error=Log in to delete posts...")


class DeleteComment(Handler):
    """
    DeleteComment: uses Handler and its helper classes to delete comments
    """
    def get(self, post_id, comment_id):
        """
        get: If the comment user id is the same as the logged in user, delete
        the comment. If not, display an error msg. If not logged in, redirect
        to login with an error msg.
        """
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/"+post_id+"?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/" + post_id + "?error=That is " +
                              "not your comment")
        else:
            self.redirect("/login?error=You must log in to " +
                          "delete your comment")


class EditComment(Handler):
    """
    EditComment: uses Handler and its helper classes to edit comments
    """
    def get(self, post_id, comment_id):
        """
        get: If the user id matches the comment's creator, allow editing.
        Otherwise, display an error msg. Redirect to login page if the browser
        is not logged in.
        """
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c.comment)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=That is not your comment")
        else:
            self.redirect("/login?error=Please log in to " +
                          "edit a post")

    def post(self, post_id, comment_id):
        """
        post: If you try to post a comment without being logged in, redirect to
        login.
        """
        if not self.user:
            return self.redirect('/login?error=Please log in...')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment',
                                   int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            if c.user_id == self.user.key().id():
                c.put()
                self.redirect('/blog/%s' % post_id)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=That is not your comment")
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
