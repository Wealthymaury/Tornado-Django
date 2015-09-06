import hashlib
import json
import logging
import signal
import time
import uuid

from collections import defaultdict
from urlparse import urlparse

from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.utils.crypto import constant_time_compare

from redis import Redis
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.options import define, parse_command_line, options
from tornado.web import Application, RequestHandler, HTTPError
from tornado.websocket import WebSocketHandler, WebSocketClosedError
from tornadoredis import Client
from tornadoredis.pubsub import BaseSubscriber

define('debug', default=True, type=bool, help='Run in debug mode')
define('port', default=3000, type=int, help='Server port')
define('allowed_hosts', multiple=True, default='localhost:8000,', help='Allowed hosts for cross domain connectinos')

class RedisSubscriber(BaseSubscriber):
	def on_message(self, msg):
		if msg and msg.kind == 'message':
			try:
				message = json.loads(msg.body)
				sender = message['sender']
				message = message['message']
			except (ValueError, KeyError):
				message = msg.body
				sender = None
			subscribers = list(self.subscribers[msg.channel].keys())
			for subscriber in subscribers:
				if sender is None or sender != subscriber.uid:
					try:
						subscriber.write_message(message)
					except tornado.websocket.WebSocketClosedError:
						# remove dead peer
						self.unsubscribe(msg.channel, subscriber)
		super(RedisSubscriber, self).on_message(msg)

# este sera quien maneje los mensajes provenientes de Django
# recibe parametros, los hace JSON y los manda usando el broadcast, el id es el channel aqui
class UpdateHandler(RequestHandler):
	def post(self, model, pk):
		self._broadcast(model, pk, 'create')

	def put(self, model, pk):
		self._broadcast(model, pk, 'update')

	def delete(self, model, pk):
		self._broadcast(model, pk, 'delete')

	def _broadcast(self, model, pk, action):
		# lo primero es seguridad
		signature = self.request.headers.get('X-Signature', None)
		
		if not signature:
			raise HTTPError(400)
		
		try:
			result = self.application.signer.unsign(signature, max_age=60 * 1)
		except ValueError:
			raise HTTPError(400)
		else:
			expected = '{method}:{url}:{body}'.format(
				method=self.request.method.lower(),
				url=self.request.full_url(),
				body=hashlib.sha256(self.request.body).hexdigest(),
			)
			if not constant_time_compare(result, expected):
				raise HTTPError(400)

		# aqui es despues de validar seguridad
		try:
			body = json.loads(self.request.body.decode('utf-8'))
		except ValueError:
			body = None

		message = json.dumps({
			'model': model,
			'id': pk,
			'action': action,
			'body': body
		})		
		self.application.broadcast(message) #OOOOOOJJJJJJOOOOOOOOO aqui es segundo parametro es el canal a donde se madaran los mensajes
		self.write("OK");

# este funciona para interaccion directa entre clientes
class MainHandler(WebSocketHandler):
	channel = None
	# este metodo fue sobreescrito
	def check_origin(self, origin):
		allowed = super(MainHandler, self).check_origin(origin)
		parsed = urlparse(origin.lower())
		matched = any(parsed.netloc == host for host in options.allowed_hosts.split(','))
		return options.debug or allowed or matched

	def open(self):
		self.sprint = None
		channel = self.get_argument('channel', None)
		if not channel:
			self.close()
		else:
			try:
				self.sprint = self.application.signer.unsign(channel, max_age=60 * 30)
			except:
				self.close();
			else:
				self.uid = uuid.uuid4().hex
				self.application.add_suscriber(self.sprint, self)

	def on_message(self, message):
		if self.sprint is not None:
			self.application.broadcast(message, channel=self.sprint, sender=self)

	def on_close(self):
		if self.sprint is not None:
			self.application.remove_subscriber(self.sprint, self)

class MyApplication(Application):
	def __init__(self, **kwargs):
		routes = [
			(r'/socket', MainHandler),
			(r'/(?P<model>user|sprint|other)/(?P<pk>[0-9]+)', UpdateHandler)
		]
		super(MyApplication, self).__init__(routes, **kwargs)
		# self.subscriptions = defaultdict(list)
		self.subscriber = RedisSubscriber(Client())
		self.publisher = Redis()
		self._key = 'tumameama' # es la misma que en django
		self.signer = TimestampSigner(self._key)

	def add_suscriber(self, channel, subscriber):
		# self.subscriptions[channel].append(subscriber)
		logging.info('Agregando '+ subscriber.uid +' al canal ' + channel)
		self.subscriber.subscribe(['all', channel], subscriber)

	def remove_subscriber(self, channel, subscriber):
		# self.subscriptions[channel].remove(subscriber)
		logging.info('Quitando '+ subscriber.uid +' al canal ' + channel)
		self.subscriber.unsubscribe(channel, subscriber)
		self.subscriber.unsubscribe('all', subscriber)

	def broadcast(self, message, channel=None, sender=None):
		channel = 'all' if channel is None else channel
		message = json.dumps({
			'sender': sender and sender.uid,
			'message': message
		})
		logging.info('Enviando '+ message +' a canal ' + channel)
		self.publisher.publish(channel, message)

	# def get_subscribers(self, channel):
	# 	return self.subscriptions[channel]

	# def broadcast(self, message, channel=None, sender=None):	
	# 	if channel is None:
	# 		for c in self.subscriptions.keys():
	# 			self.broadcast(message, channel=c, sender=sender)
	# 	else:
	# 		peers = self.get_subscribers(channel)
	# 		for peer in peers:
	# 			if peer != sender:
	# 				try:
	# 					peer.write_message(message)
	# 				except WebSocketClosedError:
	# 					# ay que quitar al peer porque quisa ya no existe
	# 					self.remove_subscriber(channel, peer)

# solo es para avizar cuando paramos el servidor
def shutdown(server):
	ioloop = IOLoop.instance()
	logging.info('Stoping server.')
	server.stop()

	def finalize():
		ioloop.stop()
		logging.info('Stoped.')

	ioloop.add_timeout(time.time() + 0.5, finalize)

if __name__ == '__main__':
	parse_command_line()
	application = MyApplication(debug=options.debug)
	server = HTTPServer(application)
	server.listen(options.port)
	signal.signal(signal.SIGINT, lambda sig, frame: shutdown(server))
	logging.info('Starting server on localhost:{}'.format(options.port))
	IOLoop.instance().start()



