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
import os
import re
import sys

import jinja2
import base64

reload(sys)
sys.setdefaultencoding('utf8')

# Jinja Environment instance necessary to use Jinja templates.
jinja_env = jinja2.Environment(
	loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), 
	autoescape=True)
jinja_env.filters['b64encode'] = base64.b64encode

REGISTER_PAGE_HTML_2 = '''\
<html>
<head>
	<meta charset="utf-8">
	<title>Registro</title>
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

					Username(*): <input type="text" name="username" value="%(username)s" placeholder="Tu nombre..." autofocus=""> <br> 
					<p class="error"> %(username_error)s </p> 

					Email(*): <input type="text" id="correo" name="email" value="%(email)s" placeholder="Tu email..." > <br>
					<p class="error"> %(email_error)s </p>

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

NEW_QUESTION_PAGE_HTML = '''\
<html>
<head>
	<meta charset="utf-8">
	<title>Añadir pregunta</title>
	<link rel="stylesheet" href="/style/estilo.css" />
	<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js" charset="UTF-8"></script>
</head>
<body class="fondo">
	<ul>
		<li class="logo"><img src="/images/QuizLogo2.png"/></li>
		<li><a href="/UserMain">Inicio</a></li>
		<li><a href="/NuevaPregunta" class="active">Añadir nueva pregunta</a></li>
		<li><a href="/VerPreguntas">Ver preguntas</a></li>
		<li class="right"><a href="/Logout">Cerrar sesión</a></li>
	</ul>

	<div style="padding:20px;margin-top:70px;">

		<div class="container">

			<form id='newQuestion' name='newQuestion' method="post">

				<div class="header">
					<h3> AÑADIR PREGUNTA </h3>
				</div>

				<div class="sep"></div>

				<div class="inputs">

					Enunciado: <input type="text" name="enunciado" value="%(enunciado)s" required autofocus=""> <br> 
					<p class="error"> %(enunciado_error)s </p> 

					Opción 1: <input type="text" id="opcion1" name="opcion1" value="%(opcionUno)s" required > <br>
					<p class="error"> %(opcionUno_error)s </p>

					Opción 2: <input type="text" id="opcion2" name="opcion2" value="%(opcionDos)s" required > <br>
					<p class="error"> %(opcionDos_error)s </p>

					Opción 3: <input type="text" id="opcion3" name="opcion3" value="%(opcionTres)s" required > <br>
					<p class="error"> %(opcionTres_error)s </p>

					Selecciona cuál será la opción correcta:
					<select name="opcionCorrecta" id="opcionCorrecta">
						<option value="OpcionUno"> Opción 1 </option>
						<option value="OpcionDos"> Opción 2 </option>
						<option value="OpcionTres"> Opción 3 </option>
					</select>

					Tema de la pregunta: <input type="text" id="tema" name="tema" value="%(tema)s" required > <br>
					<p class="error"> %(tema_error)s </p>

					<p class="error"> %(error_general)s </p>

					<p align="center">
						<input type="submit" id="submit" value="AÑADIR PREGUNTA" name="submit"> 
					</p>
				</div>
			</form>
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

class Pregunta(ndb.Model):
	enunciado = ndb.StringProperty()
	resp1 = ndb.StringProperty()
	resp2 = ndb.StringProperty()
	resp3 = ndb.StringProperty()
	respCorrecta = ndb.StringProperty()
	tema = ndb.StringProperty()
	creado = ndb.DateTimeProperty(auto_now_add = True)

class Tema(ndb.Model):
	nombre = ndb.StringProperty()
	numPreg = ndb.IntegerProperty()
	creado = ndb.DateTimeProperty(auto_now_add = True)

class Anonimo(ndb.Model):
	nick = ndb.StringProperty()
	pregCorrectas = ndb.IntegerProperty()
	pregFalladas = ndb.IntegerProperty()
	creado = ndb.DateTimeProperty(auto_now_add = True)

class UserMainHandler(session_module.BaseSessionHandler):
	def get(self):
		if (self.session.get('user')):
			user_username = self.session.get('user')
			userMain = jinja_env.get_template("templates/user_main.html")
			self.response.write(userMain.render({'welcome' : user_username}))
		else:
			self.session['redirect'] = "SI"
			self.redirect('/Login')

class MainHandler(session_module.BaseSessionHandler):
	def write_main(self, nick="", nick_error=""):
		main = jinja_env.get_template("templates/main.html")
		self.response.write(main.render({"nick" : nick, "nick_error" : nick_error}))

	def get(self):
		self.write_main()

	def post(self):
		def escape_html(s):
			return cgi.escape(s, quote=True)

		anonimo_nick = self.request.get('nick')
		sani_nick = escape_html(anonimo_nick)
		nick_error = ""

		error = False
		if not anonimo_nick:
			nick_error = "Debes introducir un nick"
			error = True

		if error:
			self.write_main(anonimo_nick, nick_error)
		else:
			anonimo = Anonimo.query(Anonimo.nick == anonimo_nick).count()
			if anonimo == 0:
				a = Anonimo()
				a.nick = anonimo_nick
				a.pregCorrectas = 0
				a.pregFalladas = 0
				a.put()
				self.session['anonimo'] = anonimo_nick
				self.redirect("/ElegirTema")
			else:
				self.session['anonimo'] = anonimo_nick
				self.redirect("/ElegirTema")

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
				self.redirect("/UserMain")
			else:
				signup_error = "Kaixo: %s <br/> Ya estabas fichad@" %user_username
				self.write_form(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error, signup_error)


class LoginHandler(session_module.BaseSessionHandler):
	def write_login_form(self, username="", password="", error=""):
		self.response.write(LOGIN_PAGE_HTML %{"username" : username, "password" : password, "error" : error})
	
	def get(self):
		if (self.session.get('redirect')):
			del self.session['redirect']
			self.response.write(LOGIN_PAGE_HTML %{"username" : "", "password" : "", "error" : "Debes iniciar sesión para acceder."})
		else:
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
			self.redirect("/UserMain")

class LogoutHandler(session_module.BaseSessionHandler):
	def get(self):
		del self.session['user']
		self.redirect('/')

class NewQuestionHandler(session_module.BaseSessionHandler):
	def write_question_form(self, enunciado="", opcionUno="", opcionDos="", opcionTres="", tema="", enunciado_error="", opcionUno_error="", opcionDos_error="", opcionTres_error="", tema_error = "", error_general=""):
		self.response.write(NEW_QUESTION_PAGE_HTML %{"enunciado" : enunciado, "opcionUno" : opcionUno, "opcionDos" : opcionDos, "opcionTres" : opcionTres, "tema" : tema, "enunciado_error" : enunciado_error, "opcionUno_error" : opcionUno_error, "opcionDos_error" : opcionDos_error, "opcionTres_error" : opcionTres_error, "tema_error" : tema_error,"error_general" : error_general})
	
	def get(self):
		if (self.session.get('user')):
			self.write_question_form()
			if self.session.get('preguntaCreada'):
				del self.session['preguntaCreada']
				self.response.write("Pregunta añadida")
		else:
			self.session['redirect'] = "SI"
			self.redirect('/Login')

	def post(self):
		def escape_html(s):
			return cgi.escape(s, quote=True)

		q_enunciado = self.request.get('enunciado')
		q_opcionUno = self.request.get('opcion1')
		q_opcionDos = self.request.get('opcion2')
		q_opcionTres = self.request.get('opcion3')
		q_opcionCorrecta = self.request.get('opcionCorrecta')
		q_tema = self.request.get('tema')
		sani_enunciado = escape_html(q_enunciado)
		sani_opcionUno = escape_html(q_opcionUno)
		sani_opcionDos = escape_html(q_opcionDos)
		sani_opcionTres = escape_html(q_opcionTres)
		sani_tema = escape_html(q_tema)
		enunciado_error = ""
		opcionUno_error = ""
		opcionDos_error = ""
		opcionTres_error = ""
		tema_error = ""
		error_general = ""

		error = False
		if not q_enunciado:
			enunciado_error = "Debes indicar un enunciado."
			error = True
		if not q_opcionUno:
			opcionUno_error = "Debes indicar tres opciones obligatoriamente."
			error = True
		if not q_opcionDos:
			opcionDos_error = "Debes indicar tres opciones obligatoriamente."
			error = True
		if not q_opcionTres:
			opcionTres_error = "Debes indicar tres opciones obligatoriamente."
			error = True
		if not q_tema:
			tema_error = "Debes indicar el tema de la pregunta."
			error = True

		if error:
			self.write_question_form(sani_enunciado, sani_opcionUno, sani_opcionDos, sani_opcionTres, sani_tema, enunciado_error, opcionUno_error, opcionDos_error, opcionTres_error, tema_error, error_general)
		else:
			pregunta = Pregunta.query(Pregunta.enunciado == q_enunciado).count()
			if pregunta == 0:
				p = Pregunta()
				p.enunciado = q_enunciado
				p.resp1 = q_opcionUno
				p.resp2 = q_opcionDos
				p.resp3 = q_opcionTres
				p.respCorrecta = q_opcionCorrecta 
				p.tema = q_tema
				p.put()
				tema = Tema.query(Tema.nombre == q_tema).count()
				if tema == 0:
					t = Tema()
					t.nombre = q_tema
					t.numPreg = 1
					t.put()
				else:
					t = Tema.query(Tema.nombre == q_tema).get()
					num = t.numPreg
					t.numPreg = num + 1
					t.put()
				self.session['preguntaCreada']="SI"
				self.redirect("/NuevaPregunta")
			else:
				error_general = "Ya había una pregunta con este enunciado. Inténtalo con una nueva."
				self.write_question_form(sani_enunciado, sani_opcionUno, sani_opcionDos, sani_opcionTres, sani_tema, enunciado_error, opcionUno_error, opcionDos_error, opcionTres_error, tema_error, error_general)

class VerPreguntasHandler(session_module.BaseSessionHandler):
	def get(self):
		if (self.session.get('user')):
			verPreg = jinja_env.get_template("templates/ver_preguntas.html")
			preguntas = Pregunta.query()
			self.response.write(verPreg.render({'preguntas' : preguntas}))
		else:
			self.session['redirect'] = "SI"
			self.redirect('/Login')

class DeleteQuestionsHandler(session_module.BaseSessionHandler):
	def get(self):
		ndb.delete_multi(Pregunta.query().iter(keys_only = True))
		ndb.delete_multi(Tema.query().iter(keys_only = True))
		self.redirect('/VerPreguntas')

class ElegirTemaHandler(session_module.BaseSessionHandler):
	def get(self):
		elegirTema = jinja_env.get_template("templates/elegir_tema.html")
		temas = Tema.query()
		self.response.write(elegirTema.render({"temas" : temas}))

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/SignUp', SignUpHandler),
	('/Login', LoginHandler),
	('/UserMain', UserMainHandler),
	('/Logout' , LogoutHandler),
	('/NuevaPregunta', NewQuestionHandler),
	('/VerPreguntas', VerPreguntasHandler),
	('/EliminarPreguntas', DeleteQuestionsHandler),
	('/ElegirTema', ElegirTemaHandler)
], config=session_module.myconfig_dict, debug=True)