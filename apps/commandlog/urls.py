from django.urls import path

from . import views

urlpatterns = [
    path("api/radius/commands", views.commands, name="api-radius-commands"),
]
