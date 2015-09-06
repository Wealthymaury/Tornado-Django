from django.conf import settings
from django.contrib.auth.models import User
from django.shortcuts import render
from django.views.generic import TemplateView

from rest_framework import viewsets

from .serializers import UserSerializer
from .mixins import UpdateHookMixin

class IndexView(TemplateView):
	template_name = 'index.html'

	def get_context_data(self, **kwargs):
		context = super(IndexView, self).get_context_data(**kwargs)
		channel = '{protocol}://{server}/{channel}'.format(
			protocol = 'wss' if settings.SOCKET_SECURE else 'ws',
			server = settings.SOCKET_SERVER,
			channel = 1 #id de la empresa y solo si el usuario tiene permiso
		)
		context.update(channel=channel)
		return context

class UserViewSet(UpdateHookMixin, viewsets.ModelViewSet):
	queryset = User.objects.all()
	serializer_class = UserSerializer
