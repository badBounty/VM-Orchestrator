from django.urls import path

from . import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('project_start/', views.project_start, name='proj_start')
]