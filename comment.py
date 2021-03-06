from google.appengine.ext import db

from user import User

# This class handles comments

class Comment(db.Model):
	user_id = db.IntegerProperty(required = True)
	post_id = db.IntegerProperty(required = True)
	comment = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def getName(self):
		user = User.by_id(self.user_id)
		return user.name