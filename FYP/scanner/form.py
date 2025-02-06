from django import forms
from django.shortcuts import render
class NetworkIPForm(forms.Form):
    network_ip = forms.CharField(label='Network IP', max_length=100)