from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class user(User):
    def __str__(self):
        return f'{self.username}'
    def __repr__(self):    
        return f'User - {self.username}'
    

class Record(models.Model):
    user=models.ForeignKey(user, on_delete=models.CASCADE)
    from_Addr=models.CharField(max_length=255)
    to_Addr=models.CharField(max_length=255)
    message_length=models.IntegerField()
    message=models.CharField(max_length=255)

    def __str__(self):
        return f"{self.user}'s network capture from {self.from_Addr} to {self.to_Addr}"