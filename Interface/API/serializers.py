#mixins
from django.contrib.auth.models import Group

from students.models import user, Student
from .modelSerializer import UserSerializer, StudentSerializer

from rest_framework import mixins, serializers
from rest_framework import generics

class StudentList(mixins.ListModelMixin,
                  mixins.CreateModelMixin,
                  generics.GenericAPIView):
    queryset=Student.objects.all()
    serializer_class=UserSerializer

    def get(self, req, *args, **kwargs):
        return self.list(req, *args, **kwargs)
    
    def post(self, req, *args, **kwargs):
        return self.create(req, *args, **kwargs)
    
class StudentDetail(mixins.RetrieveModelMixin,
                    mixins.UpdateModelMixin,
                    mixins.DestroyModelMixin,
                    generics.GenericAPIView):
    queryset= Student.objects.all()
    serializer_class=StudentSerializer

    def get(self, req, *args, **kwargs):
        return self.retrieve(req, *args, **kwargs)
    
    def put(self, req, *args, **kwargs):
        return self.update(req, *args, **kwargs)
    
    def delete(self, req, *args, **kwargs):
        return self.destroy(req, *args, **kwargs)
    

class GroupSerializers(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields= ['url', 'name']