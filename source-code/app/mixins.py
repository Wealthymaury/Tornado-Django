import hashlib
import requests # instalado con pip install requests

from django.conf import settings
from django.core.signing import TimestampSigner
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User

from rest_framework.renderers import JSONRenderer

# esta clase es la que manda las cosas a tornado segun lo que ocurre
class UpdateHookMixin(object):
	def _build_hook_url(self, obj):
		if isinstance(obj, User):
			model = 'user'
		else:
			model = obj.__class__.__name__.lower()
		
		return '{}://{}/{}/{}'.format(
			'https' if settings.SOCKET_SECURE else 'http',
			settings.SOCKET_SERVER,
			model,
			obj.pk
		)

	def _build_hook_signarute(self, method, url, body):
		signer = TimestampSigner(settings.SOCKET_SECRET)
		value = '{method}:{url}:{body}'.format(
			method=method.lower(),
			url=url,
			body=hashlib.sha256(body or b'').hexdigest()
		)
		return signer.sign(value)

	def _send_hook_request(self, obj, method):
		url = self._build_hook_url(obj)

		if method in ('POST', 'PUT'):
			serializer = self.get_serializer(obj)
			renderer = JSONRenderer()
			context = {'request': self.request}
			body = renderer.render(serializer.data, renderer_context=context)
		else:
			body = None

		headers = {
			'context-type': 'application/json',
			'X-Signature': self._build_hook_signarute(method, url, body)
		}

		try:
			print('Enviando peticion a :' + url + ' con metodo '+ method)
			response = requests.request(method, url, data=body, timeout=0.5, headers=headers)
			response.raise_for_status()
			print('Peticion enviada...')
		except requests.exceptions.ConnectionError:
			print('Error de conexion')
			# concexion rechazada
			pass
		except requests.exceptions.Timeout:
			print('Error de timeout')
			# timeout
			pass
		except requests.exceptions.RequestException, e:
			print('Error de 400 o 500', e.message)
			# error 4XX o 5XX
			pass

	def perform_create(self, serializer):
		super(UpdateHookMixin, self).perform_create(serializer)
		self._send_hook_request(serializer.instance, 'POST')

	def perform_update(self, serializer):
		super(UpdateHookMixin, self).perform_update(serializer)
		self._send_hook_request(serializer.instance, 'PUT')

	def perform_destroy(self, instance):
		self._send_hook_request(instance, 'DELETE')
		super(UpdateHookMixin, self).perform_destroy(serializer)


