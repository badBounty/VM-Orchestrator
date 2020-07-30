from django.urls import path

from . import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('start_recon/', views.run_recon_against_target, name='start_recon')
    #path('on_demand_scan/', views.on_demand_scan, name='on_demand_scan')
]