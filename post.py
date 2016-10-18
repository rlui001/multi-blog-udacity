from google.appengine.ext import db

from user import User
import get_template


# Post Class
class Post(db.Model):
	"""
		This class contains content information for blog posts.
		Stored in the database.

		Data:
			uid: id of user who wrote the post
			subject: subject of post
			content: content of post
			created: date of creation
	"""

	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	user_id = db.IntegerProperty(required = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return get_template.render_str("post.html", p = self)

	def getName(self):
		# This retrieves the user by searching the uid in database
		user = User.by_id(self.user_id)
		return user.name


# Like Class
class Like(db.Model):
	"""
		This class contains the user_id and post_id for posts.
		This is to keep track of which users liked the post, or 
		if the user created the post.
	"""
	user_id = db.IntegerProperty(required=True)
	post_id = db.IntegerProperty(required=True)

	def getName(self):
		user = User.by_id(self.user_id)
		return user.name