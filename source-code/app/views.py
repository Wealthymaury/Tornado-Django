from django.conf import settings
from django.contrib.auth.models import User
from django.core.signing import TimestampSigner
from django.views.generic import TemplateView

from rest_framework import viewsets

from .serializers import UserSerializer
from .mixins import UpdateHookMixin

class IndexView(TemplateView):
	template_name = 'index.html'

	def get_context_data(self, **kwargs):
		context = super(IndexView, self).get_context_data(**kwargs)
		signer = TimestampSigner(settings.SOCKET_SECRET)
		channel = signer.sign(1) # el 1 deberia ser el ID de la empresa
		url = '{protocol}://{server}/socket?channel={channel}'.format(
			protocol = 'wss' if settings.SOCKET_SECURE else 'ws',
			server = settings.SOCKET_SERVER,
			channel = channel
		)
		context.update(socket_url=url)
		return context

class UserViewSet(UpdateHookMixin, viewsets.ModelViewSet):
	queryset = User.objects.all()
	serializer_class = UserSerializer
