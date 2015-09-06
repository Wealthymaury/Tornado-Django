from django.conf.urls import include, url
from django.contrib import admin

from rest_framework import routers

from app.views import IndexView, UserViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet)

urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^$', IndexView.as_view()),
    url(r'^api/', include(router.urls)), # api URLs
]
