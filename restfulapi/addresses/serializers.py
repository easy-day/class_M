from .models import Addresses
from rest_framework import serializers

class AddressesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Addresses
        fields = ['name', 'phone_number','address','created']