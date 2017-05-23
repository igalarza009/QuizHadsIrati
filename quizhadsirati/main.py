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

class Usuario(ndb.Model):
	nombre = ndb.StringProperty()
	email = ndb.StringProperty()
	password = ndb.StringProperty(indexed=True)
	creado = ndb.DateTimeProperty(auto_now_add = True)

class Pregunta(ndb.Model):
	cod = ndb.StringProperty()
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
	def write_main(self, last_nick="", aciertos="", total="", onload="", nick="", nick_error=""):
		main = jinja_env.get_template("templates/main.html")
		self.response.write(main.render({"last_nick" : last_nick, "aciertos" : aciertos, "total" : total, "onload" : onload, "nick" : nick, "nick_error" : nick_error}))

	def get(self):
		if self.session.get('finJuego'):
			anon = Anonimo.query(Anonimo.nick == self.session.get('anonimo')).get()
			aciertosTotales = anon.pregCorrectas
			fallosTotales = anon.pregFalladas
			totalPreg = aciertosTotales + fallosTotales
			nick = anon.nick
			del self.session['anonimo']
			del self.session['finJuego']
			self.write_main(nick, aciertosTotales, totalPreg, "alertFinJuego()", "", "")
		else:
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
			self.write_main("", "", "", "", anonimo_nick, nick_error)
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
	def write_signup(self, username="", password="", verify="", email="", username_error="", password_error="", verify_error="", email_error="", signup_error=""):
		signup = jinja_env.get_template("templates/registro.html")
		self.response.write(signup.render({"username" : username, "password" : password, "verify" : verify, "email" : email, "username_error" : username_error, "password_error" : password_error, "verify_error" : verify_error, "email_error" : email_error, "signup_error" : signup_error}))
	
	def get(self):
		self.write_signup()

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
			self.write_signup(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error)
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
				self.write_signup(sani_username, sani_password, sani_verify, sani_email, username_error, password_error, verify_error, email_error, signup_error)


class LoginHandler(session_module.BaseSessionHandler):
	def write_login(self, username="", password="", error=""):
		login = jinja_env.get_template("templates/login.html")
		self.response.write(login.render({"username" : username, "password" : password, "error" : error}))
	
	def get(self):
		if (self.session.get('redirect')):
			del self.session['redirect']
			login = jinja_env.get_template("templates/login.html")
			self.response.write(login.render({"username" : "", "password" : "", "error" : "Debes iniciar sesión para acceder."}))
		else:
			self.write_login()

	def post(self):

		def escape_html(s):
			return cgi.escape(s, quote=True)

		user_username = self.request.get('username')
		user_password = self.request.get('pass')

		user = Usuario.query(Usuario.nombre == user_username, Usuario.password == user_password).count()
		if user == 0:
			error = "Credenciales incorrectas"
			self.write_login(user_username, user_password, error)
		else:
			self.session['user']=user_username
			self.redirect("/UserMain")

class LogoutHandler(session_module.BaseSessionHandler):
	def get(self):
		del self.session['user']
		self.redirect('/')

class NewQuestionHandler(session_module.BaseSessionHandler):
	def write_question_form(self, onload="", enunciado="", opcionUno="", opcionDos="", opcionTres="", tema="", enunciado_error="", opcionUno_error="", opcionDos_error="", opcionTres_error="", tema_error = "", error_general=""):
		newQuestionForm = jinja_env.get_template("templates/nueva_pregunta.html")
		self.response.write(newQuestionForm.render({"onload" : onload, "enunciado" : enunciado, "opcionUno" : opcionUno, "opcionDos" : opcionDos, "opcionTres" : opcionTres, "tema" : tema, "enunciado_error" : enunciado_error, "opcionUno_error" : opcionUno_error, "opcionDos_error" : opcionDos_error, "opcionTres_error" : opcionTres_error, "tema_error" : tema_error,"error_general" : error_general}))
	
	def get(self):
		if (self.session.get('user')):
			self.write_question_form()	
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
			self.write_question_form("", sani_enunciado, sani_opcionUno, sani_opcionDos, sani_opcionTres, sani_tema, enunciado_error, opcionUno_error, opcionDos_error, opcionTres_error, tema_error, error_general)
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
				num = Pregunta.query().count() + 1
				p.cod = "preg%i" %num
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
				self.write_question_form("alertNuevaPregunta()", "", "", "", "", "", "", "", "", "", "", "")
			else:
				error_general = "Ya había una pregunta con este enunciado. Inténtalo con una nueva."
				self.write_question_form("alertPregRepetida()", sani_enunciado, sani_opcionUno, sani_opcionDos, sani_opcionTres, sani_tema, enunciado_error, opcionUno_error, opcionDos_error, opcionTres_error, tema_error, error_general)

class VerPreguntasHandler(session_module.BaseSessionHandler):
	def get(self):
		if (self.session.get('user')):
			verPreg = jinja_env.get_template("templates/ver_preguntas.html")
			preguntas = Pregunta.query().order(Pregunta.cod)
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

class QuizHandler(session_module.BaseSessionHandler):
	def get(self):
		tema = self.request.get('tema')
		preguntas = Pregunta.query(Pregunta.tema == tema).order(Pregunta.cod)
		quiz = jinja_env.get_template("templates/quiz.html")
		self.response.write(quiz.render({'preguntas' : preguntas, 'tema' : tema}))

	def post(self):
		tema = self.request.get('tema')
		preguntas = Pregunta.query(Pregunta.tema == tema).order(Pregunta.cod)
		aciertos = 0
		fallos = 0

		for p in preguntas:
			user_respuesta = self.request.get(p.cod)
			if user_respuesta == p.respCorrecta:
				aciertos = aciertos + 1
			else:
				fallos = fallos + 1

		anonimo = Anonimo.query(Anonimo.nick == self.session.get('anonimo')).get()
		anonimo.pregFalladas = anonimo.pregFalladas + fallos
		anonimo.pregCorrectas = anonimo.pregCorrectas + aciertos
		anonimo.put()
		self.redirect('/Resultado?tema=%s&aciertos=%i&fallos=%i' %(tema, aciertos, fallos))

class ResultHandler(session_module.BaseSessionHandler):
	def get(self):
		tema = self.request.get('tema')
		aciertos = self.request.get('aciertos')
		fallos = self.request.get('fallos')
		resultados = jinja_env.get_template("templates/resultados.html")
		self.response.write(resultados.render({'tema' : tema, 'aciertos' : aciertos, 'fallos' : fallos}))

class FinalizarJuegoHandler(session_module.BaseSessionHandler):
	def get(self):
		self.session['finJuego'] = 'SI'
		self.redirect('/')

class ComprobarEmail(session_module.BaseSessionHandler):
	def post(self):
		EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
		email = self.request.get('email')
		if not EMAIL_RE.match(email):
			self.response.out.write('Por favor, introduzca un email válido (ejemplo@ejemplo.com)')
		else:
			self.response.out.write('Email válido')

class ComprobarPass(session_module.BaseSessionHandler):
	def post(self):
		PASSWORD_RE = re.compile(r"^.{3,20}$")
		password = self.request.get("pass")
		if not PASSWORD_RE.match(password):
			self.response.out.write('La contraseña debe tener entre 3 y 20 carácteres')
		else:
			self.response.out.write('Password válida')

class ComprobarUser(session_module.BaseSessionHandler):
	def post(self):
		USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		user = self.request.get("user")
		if not USER_RE.match(user):
			self.response.out.write('El nombre de usuario solo puede estar compuesto por letras, números y guiones (- o _) y debe tener entre 3 y 20 carácteres.')
		else:
			self.response.out.write('Nombre de usuario válido')

class ComprobarPregunta(session_module.BaseSessionHandler):
	def post(self):
		codPreg = self.request.get('codPreg')
		preg = Pregunta.query(Pregunta.cod == codPreg).get()
		respuesta = self.request.get('selectedOption')
		if respuesta == preg.respCorrecta:
			self.response.out.write('Respuesta correcta!')
		else:
			self.response.out.write('Parece que no es la respuesta correcta...')
			

app = webapp2.WSGIApplication([
	('/', MainHandler),
	('/SignUp', SignUpHandler),
	('/Login', LoginHandler),
	('/UserMain', UserMainHandler),
	('/Logout' , LogoutHandler),
	('/NuevaPregunta', NewQuestionHandler),
	('/VerPreguntas', VerPreguntasHandler),
	('/EliminarPreguntas', DeleteQuestionsHandler),
	('/ElegirTema', ElegirTemaHandler),
	('/Quiz', QuizHandler),
	('/Resultado', ResultHandler),
	('/FinalizarJuego', FinalizarJuegoHandler),
	('/comprobarEmail', ComprobarEmail),
	('/comprobarPass', ComprobarPass),
	('/comprobarUser', ComprobarUser),
	('/comprobarPregunta', ComprobarPregunta)
], config=session_module.myconfig_dict, debug=True)