from django.contrib.auth.models import Group

from rest_framework import serializers
from rest_framework.response import Response

from .models import *


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=user
        fields='__all__' 
    
    def list(self, instance):
        pass
    
    def create(self, validated_data, *args, **kwargs):
        instance = self.Meta.model.objects.create(**validated_data)
        instance.set_password(validated_data['password']) if CheckPassword(validated_data['password']) else instance.save()
        instance.save()

class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model=user
        fields=["username", "password"] 
    
    def list(self, instance):
        pass
    
    def create(self, validated_data, *args, **kwargs):
        instance = self.Meta.model.objects.create(**validated_data)
        instance.set_password(validated_data['password'])
        instance.save()
        return instance
        
class GroupSerializers(serializers.ModelSerializer):
    class Meta:
        model= Group
        fields=['url', 'name']

class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model=Student
        fields='__all__'
    
    def get(self, req, *args, **kwargs):
        return self.retrieve(req, *args, **kwargs)
    
    def put(self, req, *args, **kwargs):
        return self.update(req, *args, **kwargs)
    
    def delete(self, req, *args, **kwargs):
        return self.destroy(req, *args, **kwargs)
    


