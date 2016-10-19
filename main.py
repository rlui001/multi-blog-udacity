#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


# Code presented here is a combination of 
# both self-written code and solution-provided code from Udacity
import webapp2
import re
import hmac
import get_template

from comment import Comment
from user import User
from post import Post
from post import Like
from string import letters

from google.appengine.ext import db 


secret = 'j!)wS3Lms7eMh%5T*}9C2X6QANo-:5'

### This is for cookie validation, using hmac ###
# This function returns the hashed value in the format 'val|h(val)'
def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	# Takes val from 'val|h(val)' format and stores into val
	val = secure_val.split('|')[0]
	# If hashed format == make_secure_val(val)...
	if secure_val == make_secure_val(val):
		return val

# For validating log in
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class BlogHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		#defined globally so it can be used by other classes
		#this render_str calls the global function render_str
		params['user'] = self.user
		return get_template.render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

# Stores cookie with name, hashed val
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		# Return cookie_val if cookie_val check_secure_val(cookie_val) is true
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

# This function checks to see if user is logged in or not per each request
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))


class Signup(BlogHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		# Sets params, username and email to re-render if an error occurs

		params = dict(username = self.username, email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "Username not valid."
			error = True

		if not valid_password(self.password):
			params['error_password'] = "Password not valid."
			error = True
		elif self.password != self.verify:
			params['error_verify'] = "Password does not match."
			error = True

		if not valid_email(self.email):
			params['error_email'] = "Email is not valid."
			error = True

		# If there is an error, render the page again with params included

		if error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError

# This class inherits from parent Signup class
class Register(Signup):
	def done(self):
		# This makes sure user does not already exist in db
		u = User.by_name(self.username)
		if u:
			message = "User already exists."
			self.render('signup.html', error_username = message)
		else:
			# Creates the object and stores in database
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			#redirects to welcome page
			self.redirect('/welcome')

class Welcome(BlogHandler):
	def get(self):
		# If self.user exists, render welcome page + user of person
		# otherwise, redirect to signup page
		if self.user:
			self.render('welcome.html', username = self.user.name)
		else:
			self.redirect('/signup')

class Login(BlogHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		# Calls login method specific to class User


		u = User.login(username, password)
		if u:
			# Calls global function login
			self.login(u)
			self.redirect('/welcome')
		else:
			message = "Invalid login"
			self.render('login.html', error = message)

class Logout(BlogHandler):
	def get(self):
		self.logout()
		self.redirect('/')


# Below here contains functions and classes for the blog

# Organizes data
def blog_key(name = 'default'):
	return db.Key.from_path('blogs', name)


# This handles the front page which displays 10 latest posts
class BlogFront(BlogHandler):
	def get(self):
		del_post_id = self.request.get('del_post_id')
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
		self.render('front.html', posts = posts)

# This handles the permalink page
class PostPage(BlogHandler):
	def get(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id=" + post_id + " ORDER BY created DESC")

		likes = db.GqlQuery("SELECT * FROM Like WHERE post_id=" + post_id)

		if not post:
			self.error(404)
			return

		self.render("permalink.html", post=post, numLikes=likes.count(), comments=comments)

	def post(self, post_id):
		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if not post:
			self.error(404)
			return

		c = "this needs to be a string"

		# If user is logged in
		if self.user:
			if self.request.get('like') and self.request.get('like') == "update":
				likes = db.GqlQuery("SELECT * FROM Like WHERE post_id=" + post_id + " AND user_id=" + str(self.user.key().id()))
				# If user = creator of post, don't allow user to like post
				if self.user.key().id() == post.user_id:
					self.redirect('/'+post_id+"?error=You are not allowed to like your own post.")
				elif likes.count() == 0:
					l = Like(parent = blog_key(), user_id = self.user.key().id(), post_id = int(post_id))
					l.put()

			if self.request.get('comment'):
				c = Comment(parent = blog_key(), user_id=self.user.key().id(), post_id = int(post_id), comment = self.request.get('comment'))
				c.put()
		else:
			self.redirect('/login?error=Log in before performing tasks')

		comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id =" + post_id + "ORDER BY created DESC")

		likes = db.GqlQuery("SELECT * FROM Like WHERE post_id=" + post_id)

		self.render("permalink.html", post=post, comments=comments, numLikes=likes.count(),new=c)


# This handles the page to submit a new post
class NewPost(BlogHandler):
	def get(self):
		if self.user:
			self.render("newpost.html")
		else:
			self.redirect('/login?errormsg=Log in before performing actions')

	def post(self):
		if not self.user:
			self.redirect('/login?errormsg=Log in before performing actions')

		subject = self.request.get('subject')
		content = self.request.get('content')

		if subject and content:
			# If subject and content exists, create Post object and store into db
			p = Post(parent = blog_key(), subject=subject, content=content, user_id=self.user.key().id())
			p.put()
			# Redirects to page /objectid which shows the post itself after submission
			self.redirect('/%s' % str(p.key().id()))
		else:
			error = "There has to be a subject and content"
			# re-renders form with subject and content still in input boxes + error msg
			self.render("newpost.html", subject=subject, content=content, error=error)

class DeletePost(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if post.user_id == self.user.key().id():
				post.delete()
				self.redirect('/?del_post_id=' + post_id)
			else:
				self.redirect('/' + post_id)

		else:
			self.redirect('/login?errormsg=Log in before performing actions')

class EditPost(BlogHandler):
	def get(self, post_id):
		if self.user:
			key = db.Key.from_path('Post', int(post_id), parent=blog_key())
			post = db.get(key)
			if post.user_id == self.user.key().id():
				self.render('editpost.html',subject=post.subject,content=post.content)

			else:
				self.redirect('/' + post_id)

		else:
			self.redirect('/login?errormsg=Log in before performing actions')

	def post(self, post_id):
		if not self.user:
			self.redirect('/login?errormsg=Log in before performing actions')

		subject = self.request.get('subject')
		content = self.request.get('content')

		key = db.Key.from_path('Post', int(post_id), parent=blog_key())
		post = db.get(key)

		if post.user_id == self.user.key().id():
			if subject and content:
				key = db.Key.from_path('Post', int(post_id), parent=blog_key())
				post = db.get(key)
				post.subject = subject
				post.content = content
				post.put()
				self.redirect('/%s' % post_id)
			else:
				error = "You need a subject, and content"
				self.render('editpost.html', subject=subject, content=content, error=error)
		else:
			self.redirect('/%s?errormsg=You cannot modify this post'  % post_id)

class EditComment(BlogHandler):
	def get(self, post_id, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
			c = db.get(key)
			if c.user_id == self.user.key().id():
				self.render('editcomment.html', comment=c.comment)
			else:
				self.redirect('/' + post_id)

		else:
			self.redirect('/login?errormsg=Log in before performing actions')


	def post(self, post_id, comment_id):
		if not self.user:
			self.redirect('/login?errormsg=You must log in before you can edit comments')

		comment = self.request.get('comment')
		key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
		c = db.get(key)

		if c.user_id == self.user.key().id():
			if comment:
				key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
				c = db.get(key)
				c.comment = comment
				c.put()
				self.redirect('/%s' % post_id)
			else:
				error = "You need to enter some text"
				self.render('editcomment.html', comment=comment, error=error)
		else:
			self.redirect('/%s?errormsg=You cannot modify this comment' % post_id)

class DeleteComment(BlogHandler):
	"""
		This class is responsible for deleting comments.
	"""
	def get(self, post_id, comment_id):
		if self.user:
			key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())

			c = db.get(key)
			if c.user_id == self.user.key().id():
				c.delete()
				self.redirect('/' + post_id + '?del_comment_id=' + comment_id)

			else:
				self.redirect('/' + post_id)

		else:
			self.redirect('/login?errormsg=You must log in before performing actions')



app = webapp2.WSGIApplication([
    ('/', BlogFront), 
    ('/([0-9]+)', PostPage), 
    ('/newpost', NewPost), 
    ('/signup', Register), 
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
    ('/deletepost/([0-9]+)', DeletePost),
    ('/editpost/([0-9]+)', EditPost),
    ('/deletecomment/([0-9]+)/([0-9]+)', DeleteComment),
    ('/editcomment/([0-9]+)/([0-9]+)', EditComment)
], debug=True)
