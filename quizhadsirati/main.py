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
import sys

reload(sys)
sys.setdefaultencoding('utf8')

REGISTER_PAGE_HTML_2 = '''\
<html>
<head>
	<meta charset="utf-8">
	<title>Irania</title>
	<link rel="stylesheet" href="/style/estilo.css" />
	<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js" charset="UTF-8"></script>
</head>
<body class="fondo">
	<ul>
		<li class="logo"><img src="/images/QuizLogo2.png"/></li>
		<li><a href="/">Inicio</a></li>
		<li class="right"><a href="/SignUp" class="active">Registrarse</a></li>
		<li class="right"><a href="/Login">Login</a></li>
	</ul>

	<div style="padding:20px;margin-top:70px;">

		<div class="container">

			<form id='registro' name='registro' method="post">

				<div class="header">
					<h3> REGISTRO </h3>
				</div>

				<div class="sep"></div>

				<div class="inputs">

					<p class="error"> %(signup_error)s </p>

					Username(*): <input type="text" name="username" value="%(username)s" placeholder="Tu nombre..." required autofocus=""> <br> 
					<p class="error"> %(username_error)s </p> 

					<br/>

					Email(*): <input type="text" id="correo" name="email" value="%(email)s" required placeholder="Tu email..." > <br>
					<p class="error"> %(email_error)s </p>

					<br/>

					Password(*): <input type="password" id="password" name="password" value="%(password)s" autocomplete="off"> <br>
					<p class="error"> %(password_error)s </p>

					Repite password(*): <input type="password" name="verify" value="%(verify)s" placeholder="La misma contraseña de antes..."> <br>
					<p class="error"> %(verify_error)s </p>
	
					<p align="center">
						<input type="submit" id="submit" value="REGISTRARSE" name="submit"> 
					</p>
				</div>
			</form>
		</div>

	</div>
</body>
</html>	

'''

LOGIN_PAGE_HTML = '''\
<html>
	<head>
		<title> Login </title>
		<link rel="stylesheet" href="/style/estilo.css" />
		<meta charset="utf-8">
	</head>
	<body class="fondo">
		<ul>
			<li class="logo"><img src="/images/QuizLogo2.png"/></li>
			<li><a href="/">Inicio</a></li>
			<li class="right"><a href="/SignUp">Registrarse</a></li>
			<li class="right"><a href="/Login" class="active">Login</a></li>
		</ul>

		<div style="padding:20px;margin-top:70px;height: 700px">

			<div class="container">

				<form id="login" method="post">

					<div class="header">
						<h3> LOGIN </h3>
					</div>

				<div class="sep"> </div>

				<div class="inputs">
					<p> Username: <input type="text" required name="username" size="21" value="%(username)s" autofocus=""/> </p>
					<p> Password: <input type="password" required name="pass" size="21" value="%(password)s" /> </p>
					<p class="error"> %(error)s </p>
					<p> <input id="submit" value="ENTRAR" type="submit" /> </p>
				</div>
				</form>
			</div>

		</div>
		
	</body>
</html>
'''

MAIN_PAGE_HTML = '''\
<html>
	<head>
		<title> Inicio </title>
		<link rel="stylesheet" href="/style/estilo.css" />
		<meta charset="utf-8">
	</head>
	<body class="fondo">
		<ul>
			<li class="logo"><img src="/images/QuizLogo2.png"/></li>
			<li><a href="/" class="active">Inicio</a></li>
			<li class="right"><a href="/SignUp">Registrarse</a></li>
			<li class="right"><a href="/Login">Login</a></li>
		</ul>

		<div style="padding:20px;margin-top:70px;height: 700px">

			<div class="container">

				<h1> Hola hola </h1>

			</div>

		</div>
		
	</body>
</html>
'''

class Usuario(ndb.Model):
	nombre = ndb.StringProperty()
	email = ndb.StringProperty()
	password = ndb.StringProperty(indexed=True)
	creado = ndb.DateTimeProperty(auto_now_add = True)

class WelcomeHandler(session_module.BaseSessionHandler):
	def get(self):
		user_username = self.session.get('user')
		self.response.write('<h1> Bienvenid@ %s !!</h1>' %user_username)

class MainHandler(session_module.BaseSessionHandler):
	def get(self):
		self.response.out.write(MAIN_PAGE_HTML)

class SignUpHandler(session_module.BaseSessionHandler):
	def write_form(self, username="", password="", verify="", email="", username_error="", password_error="", verify_error="", email_error="", signup_error=""):
		self.response.write(REGISTER_PAGE_HTML_2 %{"username" : username, "password" : password, "verify" : verify, "email" : email, "username_error" : username_error, "password_error" : password_error, "verify_error" : verify_error, "email_error" : email_error, "signup_error" : signup_error})
	
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
			user = Usuario.query(Usuario.nombre == user_username, Usuario.email == user_email).count()
			if user == 0:
				u = Usuario()
				u.nombre = user_username
				u.email = user_email
				u.password = user_password
				u.put()
				self.session['user']=user_username
				self.redirect("/Welcome")
			else:
				signup_error = "Kaixo: %s <br/> Ya estabas fichad@" %user_username
				self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error, signup_error)


class LoginHandler(session_module.BaseSessionHandler):
	def write_login_form(self, username="", password="", error=""):
		self.response.write(LOGIN_PAGE_HTML %{"username" : username, "password" : password, "error" : error})
	
	def get(self):
		self.write_login_form()

	def post(self):

		def escape_html(s):
			return cgi.escape(s, quote=True)

		user_username = self.request.get('username')
		user_password = self.request.get('pass')

		user = Usuario.query(Usuario.nombre == user_username, Usuario.password == user_password).count()
		if user == 0:
			error = "Credenciales incorrectas"
			self.write_login_form(user_username, user_password, error)
		else:
			self.session['user']=user_username
			self.redirect("/Welcome")


app = webapp2.WSGIApplication([
	('/Welcome', WelcomeHandler),
	('/', MainHandler),
	('/SignUp', SignUpHandler),
	('/Login', LoginHandler),
], config=session_module.myconfig_dict, debug=True)