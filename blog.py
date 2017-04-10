import webapp2
import os
import jinja2
import hmac
import re
import random
import string
import time

from google.appengine.ext import db

# Intializing Jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Defining constants for the webpage
SECRET = 'thisissecret'
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# Helper function to quickly repopulate the blog for debugging purposes
def populate(author, num):
    for x in range(num):
        title = '%s Post %s' % (author, str(x))
        content = 'This is post %s' % str(x)
        p = Post.makepost(title=title, content=content, author=author)
        p.put()

# Create a parent key for datastore components so they can have strong association queries
def post_key(name='default'):
    return db.Key.from_path('posts', name)

def comment_key(name='default'):
    return db.Key.from_path('comments', name)

def user_key(group='default'):
    return db.Key.from_path('users', group)

# Helper function to render html
def render_str(template, **kw):
    t = jinja_env.get_template(template)
    return t.render(kw)

# Simple encrpytion using HMAC
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Password hashing and verification
def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    pw_hash = hmac.new(SECRET, (name + pw + salt)).hexdigest()
    return '%s|%s' % (salt, pw_hash)

def valid_pw(name, pw, pw_hash):
    salt = pw_hash.split('|')[0]
    return pw_hash == make_pw_hash(name, pw, salt)

# Checking signup inputs
def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

# GQL datastore entity, used to store user information
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=user_key())

    @classmethod
    def by_name(cls, name):
        return User.all().filter('name =', name).get()

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=user_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# GQL datastore entity, used to store blog post information
class Post(db.Model):
    title = db.StringProperty(required=True)            # Post Title
    content = db.TextProperty(required=True)            # Post Content
    author = db.StringProperty(required=True)           # Post Author
    created = db.DateTimeProperty(auto_now_add=True)    # When post was created
    last_modified = db.DateTimeProperty(auto_now=True)  # When post was last modified
    liked_list = db.StringListProperty()                # Who currently liked the post
    comment_num = db.IntegerProperty()                  # Number of comments the post have

    # Allow new line to be rendered in text box
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post = self)

    def get_like(self):
        return len(self.liked_list)

    def liked_by_user(self, user):
        if user in self.liked_list:
            return True
        else:
            return False

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=post_key())

    @classmethod
    def makepost(cls, title, content, author):
        return Post(parent=post_key(), title=title, content=content, author=author,
                    liked_by_user=False, comment_num=0)

# GQL datastore entity, used to store comment information
class Comment(db.Model):
    content = db.TextProperty(required=True)            # Comment content
    author = db.StringProperty(required=True)           # Comment author
    post_id = db.IntegerProperty(required=True)         # Which post id the comment is commenting on
    created = db.DateTimeProperty(auto_now_add=True)    # When the comment was created
    last_modified = db.DateTimeProperty(auto_now=True)  # When the comment was last modified

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", comment = self)

    @classmethod
    def by_id(cls, cid):
        return Comment.get_by_id(cid, parent=comment_key())

    @classmethod
    def makecomment(cls, content, author, post_id):
        return Comment(parent=comment_key(), content=content, author=author, post_id=post_id)

# General Handler helper functions
class Handler(webapp2.RequestHandler):
    # Helper functions to render html
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        return render_str(template, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Helper functions to set and reset cookies
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

# Signup handler to handle user signup
class SignupHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        login = self.request.get('login')
        signup = self.request.get('signup')

        if login:
            self.redirect('/login')
        if signup:
            have_error = False
            username = self.request.get('username')
            password = self.request.get('password')
            verify = self.request.get('verify')
            email = self.request.get('email')
            # Creating a dictonary to pass value into sighup html
            params = dict(username=username,
                          email=email)
            if not valid_username(username):
                params['error_username'] = "That's not a valid username."
                have_error = True
            if not valid_password(password):
                params['error_password'] = "That wasn't a valid password."
                have_error = True
            elif password != verify:
                params['error_verify'] = "Your passwords didn't match."
                have_error = True
            if not valid_email(email):
                params['error_email'] = "That's not a valid email."
                have_error = True
            u = User.by_name(username)
            if u:
                params['error_username'] = 'User already exist'
                have_error = True
            if have_error:
                self.render('signup.html', **params)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/blog')

# Loging handler to handle user login
class LoginHandler(Handler):
    def get(self):
        u = User.by_name('Guest')
        if not u:
            username = 'Guest'
            password = 'guest'
            email = ''
            u = User.register(username, password, email)
            u.put()
        self.render('login.html')

    def post(self):
        login = self.request.get('login')
        signup = self.request.get('signup')
        username = self.request.get('username')
        password = self.request.get('password')
        guest = self.request.get('guest')
        user_exist = True
        if login:
            # Check if username input exist in database
            u = User.by_name(username)
            if not u:
                user_exist = False
            # Login with username and password
            u = User.login(username, password)
            if u:
                self.login(u)
                self.redirect('/blog')
            # If login not successful, display appropariate error msg
            else:
                if user_exist:
                    msg = 'Invalid login, please enter the correct password'
                else:
                    msg = "User does not exist, please register a valid user"
                if username.lower() == 'guest':
                    msg = "Please use another username, 'guest' is reserved for guest users only"
                self.render('login.html', error=msg)
        if guest:
            u = User.login('Guest','guest')
            self.login(u)
            self.redirect('/blog')
        if signup:
            self.redirect('/signup')

# Logout handler, handling user logouts
class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/login')

# Blog front handler handles the display of blogs to the user
class BlogFrontHandler(Handler):
    def get(self):
        # Grab last 10 posts by time from the Post database and render them through front.html
        posts = db.GqlQuery("select * from Post order by last_modified desc limit 10")
        self.render('blogfront.html', posts = posts, currentuser=self.user.name)

    def post(self):
        # Check if newpost or showascii buttons are hit
        newpost = self.request.get('newpost')
        logout = self.request.get('logout')

        # Finding out which Like button has been clicked
        posts = db.GqlQuery("select * from Post order by last_modified desc limit 10")
        if posts:
            for p in posts:
                post_id = p.key().id()
                likepost = self.request.get("like%s" % str(post_id))
                deletepost = self.request.get("delete%s" % str(post_id))
                editpost = self.request.get("edit%s" % str(post_id))
                commentpost = self.request.get("comment%s" % str(post_id))
                if likepost:
                    self.redirect('/like/%s' % str(p.key().id()))
                if editpost:
                    self.redirect('/edit/%s' % str(p.key().id()))
                if deletepost:
                    self.redirect('/delete/%s' % str(p.key().id()))
                if commentpost:
                    self.redirect('/comment/%s' % str(p.key().id()))
        if newpost:
            self.redirect('/newpost')
        elif logout:
            self.redirect('/logout')

# Comment front handler handles the display of comments to the user
class CommentFrontHandler(Handler):
    def get(self, post_id):
        # Query for the last 10 comments for the post associated with the post_id
        comments = db.GqlQuery("select * from Comment where post_id = %s order by last_modified desc limit 10"
                               % post_id)
        # Also query for the post itself and render both comment and post
        post = Post.by_id(int(post_id))
        self.render('commentfront.html', currentuser=self.user.name, post=post, comments=comments)

    def post(self, post_id):
        newcomment = self.request.get('newcomment')
        logout = self.request.get('logout')
        back = self.request.get('back')

        # Figure out which comment was selected if edit or delete is clicked
        comments = db.GqlQuery("select * from Comment where post_id = %s order by last_modified desc limit 10"
                               % post_id)
        for c in comments:
            comment_id = c.key().id()
            editcomment = self.request.get("edit%s" % str(comment_id))
            deletecomment = self.request.get("delete%s" % str(comment_id))
            if editcomment:
                self.redirect('/editcomment/%s/%s' % (comment_id, post_id))
            if deletecomment:
                c.delete()
                p = Post.by_id(int(post_id))
                p.comment_num = p.comment_num - 1
                p.put()
                time.sleep(0.1)
                self.redirect('/comment/%s' % post_id)
        if newcomment:
            self.redirect('/newcomment/%s' % post_id)
        if back:
            self.redirect('/blog')
        if logout:
            self.redirect('/logout')

# New comment handler handles creation of new comments
class NewCommentHandler(Handler):
    def get(self, post_id):
        post = Post.by_id(int(post_id))
        self.render('newcomment.html', currentuser=self.user.name, post=post)

    def post(self, post_id):
        submit = self.request.get('submit')
        back = self.request.get('back')
        logout = self.request.get('logout')
        p = Post.by_id(int(post_id))

        if submit:
            content = self.request.get('content')
            if content:
                c = Comment.makecomment(content=content, author=self.user.name, post_id=int(post_id))
                c.put()
                p.comment_num = p.comment_num + 1
                p.put()
                time.sleep(0.1)
                self.redirect('/comment/%s' % post_id)
            else:
                error = "Please do not leave a blank comment!"
                self.render('newcomment.html', currentuser=self.user.name, error=error, content=content)
        if back:
            self.redirect('/comment/%s' % post_id)
        if logout:
            self.redirect('/logout')

# Edit comment handler handles editing of comments
class EditCommentHandler(Handler):
    def get(self, comment_id, post_id):
        c = Comment.by_id(int(comment_id))
        self.render('editcomment.html', currentuser=self.user.name, content=c.content)

    def post(self, comment_id, post_id):
        edit = self.request.get('edit')
        back = self.request.get('back')
        logout = self.request.get('logout')

        if edit:
            content = self.request.get('content')
            if content:
                c = Comment.by_id(int(comment_id))
                c.content = content
                c.put()
                time.sleep(0.1)
                self.redirect('/comment/%s' % post_id)
        if back:
            self.redirect('/comment/%s' % post_id)
        if logout:
            self.redirect('/logout')

# New Post Page Handler
class NewPostHandler(Handler):
    def get(self):
        self.render('newpost.html', currentuser=self.user.name)

    def post(self):
        # Check if submit or back button
        submit = self.request.get('submit')
        back = self.request.get('back')
        logout = self.request.get('logout')

        if back:
            self.redirect('/blog')
        elif submit:
            title = self.request.get('subject')
            content = self.request.get('content')

            if title and content:
                p = Post.makepost(title=title, content=content, author=self.user.name)
                p.put()
                self.redirect('/blog/%s' % str(p.key().id()))
            else:
                error = "Please complete both subject and content please!"
                self.render('newpost.html', currentuser=self.user.name, title=title, content=content, error=error)
        elif logout:
            self.redirect('/logout')

# Single post handler display the added post after user make new post
class SinglePostHandler(Handler):
    def get(self, post_id):
        post = Post.by_id(int(post_id))
        if not post:
            self.error(404)
            return
        self.render("newpostlink.html", post = post, currentuser=self.user.name)

    def post(self, post_id):
        back = self.request.get('back')
        logout = self.request.get('logout')
        if back:
            self.redirect('/blog')
        elif logout:
            self.redirect('/logout')

# New Post Page Handler
class EditPostHandler(Handler):
    def get(self, post_id):
        p = Post.by_id(int(post_id))
        self.render('edit.html', currentuser=self.user.name, title=p.title, content=p.content)

    def post(self, post_id):
        # Check if submit or back button
        confirm = self.request.get('confirm')
        back = self.request.get('back')
        logout = self.request.get('logout')

        if back:
            self.redirect('/blog')
        if confirm:
            title = self.request.get('subject')
            content = self.request.get('content')
            if title and content:
                p = Post.by_id(int(post_id))
                p.title = title
                p.content = content
                p.put()
                time.sleep(0.1)
                self.redirect('/blog')
            else:
                error = "Please complete both subject and content please!"
                self.render('edit.html', currentuser=self.user.name, title=title, content=content, error=error)
        if logout:
            self.redirect('/logout')

# Delete post handler help with deleting posts
class DeletePostHandler(Handler):
    def get(self, post_id):
        p = Post.by_id(int(post_id))
        self.render('delete.html', currentuser=self.user.name, post=p)

    def post(self, post_id):
        delete = self.request.get('delete')
        back = self.request.get('back')
        logout = self.request.get('logout')

        if back:
            self.redirect('/blog')
        if delete:
            p = Post.by_id(int(post_id))
            p.delete()
            time.sleep(0.1)
            self.redirect('/blog')
        if logout:
            self.redirect('/logout')

# Like handler helps with managing likes for the posts
class LikePostHandler(Handler):
    def get(self, post_id):
        p = Post.by_id(int(post_id))
        self.render('like.html', currentuser=self.user.name, post=p)

    def post(self, post_id):
        likepost = self.request.get('likepost')
        back = self.request.get('back')
        logout = self.request.get('logout')

        if back:
            self.redirect('/blog')
        if likepost:
            p = Post.by_id(int(post_id))
            p.liked_list.append(str(self.user.name))
            p.put()
            time.sleep(0.1)
            self.redirect('/blog')
        if logout:
            self.redirect('/logout')

class DebugHandler(Handler):
    def get(self):
        self.render('debug.html', value="Debug")

    def post(self):
        clearuser = self.request.get('clearuser')
        clearpost = self.request.get('clearpost')
        clearcomment = self.request.get('clearcomment')
        pop = self.request.get('populate')

        if clearuser:
            user = User.all()
            if user:
                for u in user:
                    u.delete()
        if clearpost:
            post = Post.all()
            if post:
                for p in post:
                    p.delete()
        if clearcomment:
            comment = Comment.all()
            if comment:
                for c in comment:
                    c.delete()
        if pop:
            for name in ['Terry', 'Cindy', 'Ricky', 'Arvin', 'Mika']:
                populate(name, 2)
        self.redirect('/')


app = webapp2.WSGIApplication([('/', LoginHandler),
                               ('/debug', DebugHandler),
                               ('/login', LoginHandler),
                               ('/signup', SignupHandler),
                               ('/logout', LogoutHandler),
                               ('/blog', BlogFrontHandler),
                               ('/blog/([0-9]+)', SinglePostHandler),
                               ('/newpost', NewPostHandler),
                               ('/edit/([0-9]+)', EditPostHandler),
                               ('/delete/([0-9]+)', DeletePostHandler),
                               ('/like/([0-9]+)', LikePostHandler),
                               ('/comment/([0-9]+)', CommentFrontHandler),
                               ('/newcomment/([0-9]+)', NewCommentHandler),
                               ('/editcomment/([0-9]+)/([0-9]+)', EditCommentHandler)],
                              debug=True)




