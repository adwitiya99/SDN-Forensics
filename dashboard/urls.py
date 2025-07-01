from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('devices/', views.devices, name='devices'),
    path('pingstats/', views.ping_statistics_view, name='pingstats'),
    path('applications/', views.applications, name='applications' ),
    path('activity_log/', views.activity_log, name='activity_log'),
    path('ports/', views.ports, name='ports'),
    path('flows/', views.flows, name='flows'),
    path('flows/download/', views.download_flows, name='download_flows'),
    path('networkconfiguration/', views.networkconfiguration, name='networkconfiguration'),
    path('networkconfiguration/download/', views.download_networkconfiguration, name='download_networkconfiguration'),
    path('port_control/', views.port_control, name='port_control'),
    path("ddos_detection/", views.ddos_detection_view, name="ddos_detection"),
    path("entropy_graph/", views.entropy_graph, name="entropy_graph"),
    path('block_traffic/', views.block_traffic, name='block_traffic'),




]
