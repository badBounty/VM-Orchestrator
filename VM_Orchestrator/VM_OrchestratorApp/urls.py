from django.urls import path

from VM_OrchestratorApp import views

app_name = 'VM_OrchestratorApp'
urlpatterns = [
    # API
    path('start_recon/', views.run_recon_against_target, name='start_recon'),
    path('get_resources/', views.get_all_resources, name='get_resources'),
    path('get_vulnerabilities/', views.get_all_vulnerabilities, name='get_vulnerabilities'),
    path('approve_resources/', views.approve_resources, name='approved_scan'),
    path('update_elasticsearch/', views.force_update_elasticsearch, name='update_elasticsearch'),
    path('sync_redmine/', views.force_redmine_sync, name='sync_redmine'),
    path('add_mongo_vulns_to_redmine/', views.add_mongo_vulns_to_redmine, name='add_mongo_vulns_to_redmine'),
    path('on_demand_scan/', views.on_demand_scan, name='on_demand_scan'), ## ON DEMAND
    # Views
    path('', views.index, name='index'),
    path('test_html/', views.test_html, name='test_html'),
    path('activos/', views.activos, name='dashboard_activo'),
    path('vulns/', views.vulns, name='dashboard_vuln'),
    #
    path('current_resources/', views.current_resources, name='current_resources'),
    path('new_resource/', views.new_resource, name='new_resource'),
    path('current_vulnerabilities/', views.current_vulnerabilities, name='current_vulnerabilities'),
    path('new_vulnerability/', views.new_vulnerability, name='new_vulnerability')
]