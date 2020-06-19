from django.urls import path

from . import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('on_demand_scan/', views.on_demand_scan, name='on_demand_scan')
]