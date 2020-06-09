from django.urls import path

from . import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('test/', views.test, name='test')
]