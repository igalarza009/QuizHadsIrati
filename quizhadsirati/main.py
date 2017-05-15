#!/usr/bin/env python
# coding=utf-8
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
import webapp2
from webapp2_extras import sessions
import session_module
from google.appengine.api import users
from google.appengine.ext import ndb
import cgi
import re

REGISTER_PAGE_HTML = '''\
<!doctype html>
<html>
	<head>
		<title> Registro </title>
		<style type="text/css">
			.label {text-align: right}
			.error {color: red}
		</style>
	</head>
	<body>
		<h1> REGISTRO </h1>
		<h2> Rellene los campos por favor: </h2>
		<form method="post">
			<table>
				<tr>
					<td class="label"> Nombre del Usuario </td>
					<td> <input type="text" name="username" value="%(username)s" placeholder="Tu nombre..."> </td>
					<td class="error"> %(username_error)s </td>
				</tr>
				<tr>
					<td class="label"> Password </td>
					<td> <input type="password" name="password" value="%(password)s" autocomplete="off"> </td>
					<td class="error"> %(password_error)s </td>
				</tr>
				<tr>
					<td class="label"> Repetir Password </td>
					<td> <input type="password" name="verify" value="%(verify)s" placeholder="La misma contraseña de antes..."> </td>
					<td class="error"> %(verify_error)s </td>
				</tr>
				<tr>
					<td class="label"> Email </td>
					<td> <input type="text" name="email" value="%(email)s" placeholder="Tu email..."> </td>
					<td class="error"> %(email_error)s </td>
				</tr>
			</table>
			<input type="submit">
		</form>
	</body>
</html>
'''

class Visitante(ndb.Model):
	nombre = ndb.StringProperty()
	email = ndb.StringProperty()
	password = ndb.StringProperty(indexed=True)
	creado = ndb.DateTimeProperty(auto_now_add = True)

class WelcomeHandler(session_module.BaseSessionHandler):
	def get(self):
		user_username = self.request.get('username')
		self.response.write('<h1> Bienvenido %s !!</h1>' %user_username)

class MainHandler(session_module.BaseSessionHandler):
	def get(self):
		user = users.get_current_user()
		if user:
			greeting = ('Saludos, %s <p> <a href="%s"> Sign out</a><br>' %(user.nickname(), users.create_logout_url('/')))
			self.response.out.write('<html> <body> <h1>%s</h1></body> </html>' %greeting)
		else:
			self.redirect(users.create_login_url(self.request.uri))

class SignUpHandler(session_module.BaseSessionHandler):
	def write_form(self, username="", password="", verify="", email="", username_error="", password_error="", verify_error="", email_error=""):
		self.response.write(REGISTER_PAGE_HTML %{"username" : username, "password" : password, "verify" : verify, "email" : email, "username_error" : username_error, "password_error" : password_error, "verify_error" : verify_error, "email_error" : email_error})
	
	def get(self):
		self.write_form()

	def post(self):

		def escape_html(s):
			return cgi.escape(s, quote=True)

		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_email = self.request.get('email')
		sani_username = escape_html(user_username)
		sani_password = escape_html(user_password)
		sani_verify = escape_html(user_verify)
		sani_email = escape_html(user_email)
		username_error = ""
		password_error = ""
		verify_error = ""
		email_error = ""

		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		PASSWORD_RE = re.compile(r"^.{3,20}$")
		EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

		def valid_username(username):
			return USER_RE.match(username)

		def valid_password(password):
			return PASSWORD_RE.match(password)

		def valid_email(email):
			return EMAIL_RE.match(email)

		error = False
		if not valid_username(user_username):
			username_error = "Nombre incorrecto!"
			error = True
		if not valid_password(user_password):
			password_error = "Password incorrecta!"
			error = True
		if not user_verify or not user_password == user_verify:
			verify_error = "Password no coincide!"
			error = True
		if not valid_email(user_email):
			email_error = "Email incorrecto!"
			error = True

		if error:
			self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error)
		else:
			user = Visitante.query(Visitante.nombre == user_username, Visitante.email == user_email).count()
			if user == 0:
				u = Visitante()
				u.nombre = user_username
				u.email = user_email
				u.password = user_password
				u.put()
				self.redirect("/Welcome?username=%s" %user_username)
			else:
				self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error)
				self.response.write("Kaixo: %s <p> Ya estabas fichado" %user_username)

app = webapp2.WSGIApplication([
	('/Welcome', WelcomeHandler),
	('/', MainHandler),
	('/SignUp', SignUpHandler),
], config=session_module.myconfig_dict, debug=True)