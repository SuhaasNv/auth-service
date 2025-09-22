from django.contrib import admin
from django.urls import path
from users.views import RegisterView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/login/", TokenObtainPairView.as_view(), name="login"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]
# -- appended by security patch: introspection & logout endpoints --
from .introspection import introspect, logout_and_blacklist
from django.urls import path

urlpatterns += [
    path("api/introspect/", introspect, name="introspect"),
    path("api/logout/", logout_and_blacklist, name="logout_blacklist"),
]
