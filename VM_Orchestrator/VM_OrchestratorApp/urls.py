from django.urls import path

from VM_OrchestratorApp import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('start_recon/', views.run_recon_against_target, name='start_recon'),
    path('get_resources/', views.get_resources_from_target, name='get_resources'),
    path('on_demand_scan/', views.on_demand_scan, name='on_demand_scan'),
    path('update_elasticsearch/', views.force_update_elasticsearch, name='update_elasticsearch/'),
    path('sync_redmine/', views.force_redmine_sync, name='sync_redmine/'),
    path('start_scan_on_approved', views.start_scan_on_approved, name='approved_scan')
]