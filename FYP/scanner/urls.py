from django.urls import path
from .views import index, network_ip, scan, scan_ip,my_api_endpoint 
from scanner import views
urlpatterns = [
    path('', index, name='index'),
    path('indexscan', views.indexscan, name='indexscan'),
    path('about', views.about, name='about'),
    path('scanmain', views.scanmain, name='scanmain'),
    path('compsysscan', views.compsysscan, name='compsysscan'),
    path('contactus', views.contactus, name='contactus'),
    path('networkscan', views.networkscan, name='networkscan'),
    path('webscan', views.webscan, name='webscan'),
    path('scan/', scan, name='scan'),
    path('scan_ip/', scan_ip, name='scan_ip'),
    path('network_ip/', network_ip, name='network_ip'),
    path('api/my-endpoint/', my_api_endpoint, name='my_api_endpoint'),
]
