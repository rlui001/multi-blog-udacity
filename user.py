import random
import hashlib

from string import letters
from google.appengine.ext import db

# Functions used to hash/validate
def make_salt():
	return ''.join(random.choice(letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h,salt)

def valid_pw(name, pw, h):
	val = h.split(',')[1]
	a = hashlib.sha256(name + pw + val).hexdigest()
	b = '%s,%s' % (a,val)
	if b == h:
		return True
	else:
		return False

def users_key(group = 'default'):
	return db.Key.from_path('users', group)


# User class
class User(db.Model):
	"""
		This User class holds user information and is 
		stored in the database. 

		Data:
			name: Name of user
			pw_hash: Hashed password value
			email: Email, optional
	"""
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email=None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(), name=name, pw_hash=pw_hash, email=email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u