import json
import logging
import signal
import time

from collections import defaultdict
from urlparse import urlparse

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.options import define, parse_command_line, options
from tornado.web import Application, RequestHandler
from tornado.websocket import WebSocketHandler, WebSocketClosedError

define('debug', default=True, type=bool, help='Run in debug mode')
define('port', default=3000, type=int, help='Server port')
define('allowed_hosts', multiple=True, default='localhost:8000,', help='Allowed hosts for cross domain connectinos')

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
		message = json.dumps({
			'model': model,
			'id': pk,
			'action': action,
		})		
		self.application.broadcast(message)
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

	def open(self, channel):
		self.channel = channel
		self.application.add_suscriber(self.channel, self)

	def on_message(self, message):
		self.application.broadcast(message, channel=self.channel, sender=self)

	def on_close(self):
		self.application.remove_subscriber(self.channel, self)

class MyApplication(Application):
	def __init__(self, **kwargs):
		routes = [
			(r'/(?P<channel>[0-9]+)', MainHandler),
			(r'/(?P<model>user|sprint|other)/(?P<pk>[0-9]+)', UpdateHandler)
		]
		super(MyApplication, self).__init__(routes, **kwargs)
		self.subscriptions = defaultdict(list)

	def add_suscriber(self, channel, subscriber):
		self.subscriptions[channel].append(subscriber)

	def remove_subscriber(self, channel, subscriber):
		self.subscriptions[channel].remove(subscriber)

	def get_subscribers(self, channel):
		return self.subscriptions[channel]

	def broadcast(self, message, channel=None, sender=None):	
		if channel is None:
			for c in self.subscriptions.keys():
				self.broadcast(message, channel=c, sender=sender)
		else:
			peers = self.get_subscribers(channel)
			for peer in peers:
				if peer != sender:
					try:
						peer.write_message(message)
					except WebSocketClosedError:
						# ay que quitar al peer porque quisa ya no existe
						self.remove_subscriber(channel, peer)

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



